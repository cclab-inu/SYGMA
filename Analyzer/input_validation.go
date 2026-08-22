package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	syscallAvailabilityImplemented       = "implemented"
	syscallAvailabilityUnavailableSlot   = "unavailable_table_slot"
	syscallAvailabilityUnavailableConfig = "unavailable_config_stub"
	syscallAvailabilityUnresolvedLink    = "unresolved_link_symbol"
	syscallAvailabilityUnverified        = "unverified"
)

type BuildArtifactStatus struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	SHA256  string `json:"sha256,omitempty"`
}

type InputValidation struct {
	Performed                  bool                           `json:"performed"`
	Strict                     bool                           `json:"strict"`
	Status                     string                         `json:"status"`
	KernelRoot                 string                         `json:"kernel_root"`
	BuildRoot                  string                         `json:"build_root,omitempty"`
	CompileDatabase            string                         `json:"compile_database,omitempty"`
	CompileDatabaseSHA256      string                         `json:"compile_database_sha256,omitempty"`
	ConfigPath                 string                         `json:"config_path,omitempty"`
	SourceConfigPath           string                         `json:"source_config_path,omitempty"`
	BuildConfigPath            string                         `json:"build_config_path,omitempty"`
	ConfigSHA256               string                         `json:"config_sha256,omitempty"`
	SourceConfigSHA256         string                         `json:"source_config_sha256,omitempty"`
	BuildConfigSHA256          string                         `json:"build_config_sha256,omitempty"`
	SourceAndBuildConfigsMatch bool                           `json:"source_and_build_configs_match"`
	ConfigBuiltinSymbols       int                            `json:"config_builtin_symbols"`
	ConfigModuleSymbols        int                            `json:"config_module_symbols"`
	ConfigDisabledSymbols      int                            `json:"config_disabled_symbols"`
	ScanAll                    bool                           `json:"scan_all"`
	CompileCommandCount        int                            `json:"compile_command_count"`
	InvalidCompileCommands     int                            `json:"invalid_compile_commands"`
	UniqueCompileSources       int                            `json:"unique_compile_sources"`
	DuplicateCompileSources    int                            `json:"duplicate_compile_sources"`
	AuxiliaryCompileVariants   int                            `json:"auxiliary_compile_variants"`
	AmbiguousCompileVariants   int                            `json:"ambiguous_compile_variants"`
	MissingCompileSources      []string                       `json:"missing_compile_sources,omitempty"`
	CompileSourcesNewerThanDB  []string                       `json:"compile_sources_newer_than_database,omitempty"`
	OutsideAnalysisTrees       []string                       `json:"outside_analysis_trees,omitempty"`
	CompileOutputsChecked      int                            `json:"compile_outputs_checked"`
	MissingCompileOutputs      []string                       `json:"missing_compile_outputs,omitempty"`
	CompileOutputsOlderThanSrc []string                       `json:"compile_outputs_older_than_source,omitempty"`
	CompileOutputsOlderThanCfg []string                       `json:"compile_outputs_older_than_config,omitempty"`
	CompileOutputsOlderThanDep []string                       `json:"compile_outputs_older_than_relevant_config_dependency,omitempty"`
	CompileOutputsOutsideBuild []string                       `json:"compile_outputs_outside_build_tree,omitempty"`
	CommandsWithoutOutput      []string                       `json:"compile_commands_without_output,omitempty"`
	MissingKbuildCommandFiles  []string                       `json:"missing_kbuild_command_files,omitempty"`
	KbuildConfigDepsChecked    int                            `json:"kbuild_config_dependencies_checked"`
	ConfigOldOutputsVerified   int                            `json:"config_old_outputs_verified_by_kbuild_dependencies"`
	MissingModuleArtifacts     []string                       `json:"missing_module_artifacts,omitempty"`
	ModuleManifestEntries      int                            `json:"module_manifest_entries"`
	Artifacts                  map[string]BuildArtifactStatus `json:"artifacts"`
	SyscallTableEntries        int                            `json:"syscall_table_entries"`
	ImplementedSyscalls        int                            `json:"implemented_syscalls"`
	UnavailableTableSlots      int                            `json:"unavailable_table_slots"`
	UnavailableConfigStubs     int                            `json:"unavailable_config_stubs"`
	UnresolvedLinkSymbols      int                            `json:"unresolved_link_symbols"`
	Reasons                    []string                       `json:"reasons,omitempty"`
	Warnings                   []string                       `json:"warnings,omitempty"`
}

func (a *Analyzer) validateAnalysisInput() error {
	validation := a.inputValidation
	validation.Performed = true
	validation.Strict = !a.cfg.AllowIncompleteInput
	validation.KernelRoot = a.cfg.KernelRoot
	validation.CompileDatabase = a.cfg.CompileDB
	validation.CompileDatabaseSHA256, _ = hashFileIfPresent(a.cfg.CompileDB)
	validation.ConfigPath = a.configPath
	validation.ScanAll = a.cfg.ScanAll
	validation.SyscallTableEntries = len(a.syscalls)
	validation.Artifacts = make(map[string]BuildArtifactStatus)

	reasons := orderedSet(validation.Reasons)
	warnings := orderedSet(validation.Warnings)
	if a.cfg.Frontend != "hybrid" {
		reasons.add("final certification requires the hybrid Clang AST/CFG frontend")
	}
	if a.cfg.CompileDB == "" {
		reasons.add("final certification requires a configured compile database")
	}
	if !a.cfg.ScanAll {
		reasons.add("final certification requires -scan-all=true")
	}
	if !a.hasKernelConfig {
		reasons.add("the analyzed build configuration (.config) is missing")
	}

	buildRoot := ""
	if a.cfg.CompileDB != "" {
		buildRoot = filepath.Dir(a.cfg.CompileDB)
	}
	validation.BuildRoot = buildRoot
	sourceConfig := filepath.Join(a.cfg.KernelRoot, ".config")
	buildConfig := ""
	if buildRoot != "" {
		buildConfig = filepath.Join(buildRoot, ".config")
	}
	validation.SourceConfigPath = sourceConfig
	validation.BuildConfigPath = buildConfig
	validation.SourceConfigSHA256, _ = hashFileIfPresent(sourceConfig)
	validation.BuildConfigSHA256, _ = hashFileIfPresent(buildConfig)
	if a.configPath != "" {
		validation.ConfigSHA256, _ = hashFileIfPresent(a.configPath)
		if states, err := countKernelConfigStates(a.configPath); err == nil {
			validation.ConfigBuiltinSymbols = states.builtin
			validation.ConfigModuleSymbols = states.modules
			validation.ConfigDisabledSymbols = states.disabled
			if states.modules >= 1000 {
				warnings.add(fmt.Sprintf(
					"the configured kernel enables %d module symbols; this is valid but substantially expands compile-database, ops-table, and frontend analysis scope",
					states.modules,
				))
			}
		} else {
			warnings.add("cannot summarize analyzed kernel .config: " + err.Error())
		}
	}
	switch {
	case buildRoot != "" && validation.BuildConfigSHA256 == "":
		reasons.add("the compile database build directory has no .config")
	case validation.SourceConfigSHA256 != "" && validation.BuildConfigSHA256 != "":
		validation.SourceAndBuildConfigsMatch =
			validation.SourceConfigSHA256 == validation.BuildConfigSHA256
		if !validation.SourceAndBuildConfigsMatch {
			warnings.add("source-tree and build-tree .config files differ; the compile-database build-tree .config is authoritative")
		}
	default:
		validation.SourceAndBuildConfigsMatch = true
		if validation.SourceConfigSHA256 == "" {
			warnings.add("source-tree .config is absent; the build-tree .config is authoritative")
		}
	}

	if buildRoot != "" {
		requiredArtifacts := []string{"vmlinux", "System.map"}
		if a.configSymbols["CONFIG_MODULES"] {
			requiredArtifacts = append(requiredArtifacts, "modules.order", "modules.builtin")
		}
		for _, name := range requiredArtifacts {
			path := filepath.Join(buildRoot, name)
			status := BuildArtifactStatus{Path: path}
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				status.Present = true
				if name == "System.map" || name == "modules.order" || name == "modules.builtin" {
					status.SHA256, _ = hashFileIfPresent(path)
				}
			} else {
				reasons.add("required completed-build artifact is missing: " + path)
			}
			validation.Artifacts[name] = status
		}
		autoConfigPath := filepath.Join(buildRoot, "include", "config", "auto.conf")
		autoConfig := BuildArtifactStatus{Path: autoConfigPath}
		if info, err := os.Stat(autoConfigPath); err == nil && !info.IsDir() {
			autoConfig.Present = true
			autoConfig.SHA256, _ = hashFileIfPresent(autoConfigPath)
		} else {
			reasons.add("generated build configuration is missing: " + autoConfigPath)
		}
		validation.Artifacts["include/config/auto.conf"] = autoConfig
		if a.configSymbols["CONFIG_MODULES"] {
			modulesOrder := filepath.Join(buildRoot, "modules.order")
			if file, err := os.Open(modulesOrder); err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					module := strings.TrimSpace(scanner.Text())
					if module == "" {
						continue
					}
					validation.ModuleManifestEntries++
					path := module
					if !filepath.IsAbs(path) {
						path = filepath.Join(buildRoot, filepath.FromSlash(module))
					}
					if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
						validation.MissingModuleArtifacts = append(
							validation.MissingModuleArtifacts,
							filepath.Clean(path),
						)
					}
				}
				if scanErr := scanner.Err(); scanErr != nil {
					reasons.add("cannot read modules.order: " + scanErr.Error())
				}
				_ = file.Close()
			}
		}
	}

	compileDBInfo, _ := os.Stat(a.cfg.CompileDB)
	for source := range a.compileUnits {
		sourceInfo, err := os.Stat(source)
		if err != nil {
			validation.MissingCompileSources = append(validation.MissingCompileSources, source)
			continue
		}
		if compileDBInfo != nil && sourceInfo.ModTime().After(compileDBInfo.ModTime()) {
			validation.CompileSourcesNewerThanDB = append(
				validation.CompileSourcesNewerThanDB,
				source,
			)
		}
		if !pathWithin(a.cfg.KernelRoot, source) && (buildRoot == "" || !pathWithin(buildRoot, source)) {
			validation.OutsideAnalysisTrees = append(validation.OutsideAnalysisTrees, source)
		}
	}
	sort.Strings(validation.MissingCompileSources)
	sort.Strings(validation.CompileSourcesNewerThanDB)
	sort.Strings(validation.OutsideAnalysisTrees)
	if len(validation.MissingCompileSources) > 0 {
		reasons.add(fmt.Sprintf(
			"compile database references %d missing source file(s)",
			len(validation.MissingCompileSources),
		))
	}
	if len(validation.CompileSourcesNewerThanDB) > 0 {
		reasons.add(fmt.Sprintf(
			"%d compiled source file(s) are newer than compile_commands.json",
			len(validation.CompileSourcesNewerThanDB),
		))
	}
	if len(validation.OutsideAnalysisTrees) > 0 {
		reasons.add(fmt.Sprintf(
			"compile database references %d source file(s) outside the source/build trees",
			len(validation.OutsideAnalysisTrees),
		))
	}
	configInfo, _ := os.Stat(buildConfig)
	for source, command := range a.compileUnits {
		output := compileCommandOutput(command)
		if output == "" {
			validation.CommandsWithoutOutput = append(validation.CommandsWithoutOutput, source)
			continue
		}
		validation.CompileOutputsChecked++
		if buildRoot != "" && !pathWithin(buildRoot, output) {
			validation.CompileOutputsOutsideBuild = append(
				validation.CompileOutputsOutsideBuild,
				output,
			)
		}
		outputInfo, err := os.Stat(output)
		if err != nil || outputInfo.IsDir() {
			validation.MissingCompileOutputs = append(validation.MissingCompileOutputs, output)
			continue
		}
		sourceInfo, sourceErr := os.Stat(source)
		if sourceErr == nil && sourceInfo.ModTime().After(outputInfo.ModTime()) {
			validation.CompileOutputsOlderThanSrc = append(
				validation.CompileOutputsOlderThanSrc,
				output,
			)
		}
		if configInfo != nil && configInfo.ModTime().After(outputInfo.ModTime()) {
			validation.CompileOutputsOlderThanCfg = append(
				validation.CompileOutputsOlderThanCfg,
				output,
			)
			check, checkErr := checkKbuildConfigFreshness(
				buildRoot,
				output,
				outputInfo.ModTime(),
			)
			if checkErr != nil {
				validation.MissingKbuildCommandFiles = append(
					validation.MissingKbuildCommandFiles,
					kbuildCommandFile(output),
				)
				continue
			}
			validation.KbuildConfigDepsChecked += check.DependenciesChecked
			if len(check.NewerDependencies) == 0 {
				validation.ConfigOldOutputsVerified++
			} else {
				validation.CompileOutputsOlderThanDep = append(
					validation.CompileOutputsOlderThanDep,
					output,
				)
			}
		}
	}
	sort.Strings(validation.CommandsWithoutOutput)
	sort.Strings(validation.MissingCompileOutputs)
	sort.Strings(validation.CompileOutputsOlderThanSrc)
	sort.Strings(validation.CompileOutputsOlderThanCfg)
	sort.Strings(validation.CompileOutputsOlderThanDep)
	sort.Strings(validation.CompileOutputsOutsideBuild)
	sort.Strings(validation.MissingKbuildCommandFiles)
	sort.Strings(validation.MissingModuleArtifacts)
	if len(validation.CommandsWithoutOutput) > 0 {
		reasons.add(fmt.Sprintf(
			"%d primary compile command(s) have no object output",
			len(validation.CommandsWithoutOutput),
		))
	}
	if len(validation.MissingCompileOutputs) > 0 {
		reasons.add(fmt.Sprintf(
			"%d compile database object output(s) are missing; the build or database is incomplete",
			len(validation.MissingCompileOutputs),
		))
	}
	if len(validation.CompileOutputsOlderThanSrc) > 0 {
		reasons.add(fmt.Sprintf(
			"%d compile database object output(s) are older than their source",
			len(validation.CompileOutputsOlderThanSrc),
		))
	}
	if len(validation.CompileOutputsOlderThanDep) > 0 {
		reasons.add(fmt.Sprintf(
			"%d compile database object output(s) are older than a relevant Kbuild-recorded CONFIG_* dependency",
			len(validation.CompileOutputsOlderThanDep),
		))
	}
	if len(validation.MissingKbuildCommandFiles) > 0 {
		reasons.add(fmt.Sprintf(
			"%d object output(s) predate .config and lack Kbuild .cmd metadata needed to prove config freshness",
			len(validation.MissingKbuildCommandFiles),
		))
	}
	if len(validation.CompileOutputsOlderThanCfg) > 0 &&
		len(validation.CompileOutputsOlderThanDep) == 0 &&
		len(validation.MissingKbuildCommandFiles) == 0 {
		warnings.add(fmt.Sprintf(
			"%d object output(s) predate .config but are fresh against their Kbuild-recorded CONFIG_* dependencies",
			len(validation.CompileOutputsOlderThanCfg),
		))
	}
	if len(validation.CompileOutputsOutsideBuild) > 0 {
		reasons.add(fmt.Sprintf(
			"%d compile database object output(s) are outside the build tree",
			len(validation.CompileOutputsOutsideBuild),
		))
	}
	if len(validation.MissingModuleArtifacts) > 0 {
		reasons.add(fmt.Sprintf(
			"%d module artifact(s) listed in modules.order are missing",
			len(validation.MissingModuleArtifacts),
		))
	}
	if validation.AmbiguousCompileVariants > 0 {
		reasons.add(fmt.Sprintf(
			"%d source file(s) have multiple non-equivalent primary compile commands",
			validation.AmbiguousCompileVariants,
		))
	}
	if validation.InvalidCompileCommands > 0 {
		reasons.add(fmt.Sprintf(
			"%d compile database entries have no directory or source file",
			validation.InvalidCompileCommands,
		))
	}
	if buildRoot != "" {
		vmlinuxInfo, _ := os.Stat(filepath.Join(buildRoot, "vmlinux"))
		if configInfo != nil && vmlinuxInfo != nil &&
			configInfo.ModTime().After(vmlinuxInfo.ModTime()) {
			reasons.add("vmlinux is older than the build-tree .config")
		}
		if configInfo != nil && compileDBInfo != nil &&
			configInfo.ModTime().After(compileDBInfo.ModTime()) {
			reasons.add("compile_commands.json is older than the build-tree .config")
		}
	}

	systemMapPath := ""
	if buildRoot != "" {
		systemMapPath = filepath.Join(buildRoot, "System.map")
	}
	symbols, symbolErr := loadSystemMap(systemMapPath)
	if symbolErr != nil {
		if !errors.Is(symbolErr, os.ErrNotExist) {
			reasons.add("cannot parse System.map: " + symbolErr.Error())
		}
	} else {
		a.classifySyscallAvailability(symbols)
	}
	for _, entry := range a.syscalls {
		switch entry.Availability {
		case syscallAvailabilityImplemented:
			validation.ImplementedSyscalls++
		case syscallAvailabilityUnavailableSlot:
			validation.UnavailableTableSlots++
		case syscallAvailabilityUnavailableConfig:
			validation.UnavailableConfigStubs++
		case syscallAvailabilityUnresolvedLink:
			validation.UnresolvedLinkSymbols++
		}
	}
	if symbolErr == nil && validation.UnresolvedLinkSymbols > 0 {
		reasons.add(fmt.Sprintf(
			"%d non-empty syscall table entries have no linked x86-64 symbol in System.map",
			validation.UnresolvedLinkSymbols,
		))
	}

	validation.Reasons = reasons.slice()
	validation.Warnings = warnings.slice()
	if len(validation.Reasons) == 0 {
		validation.Status = "complete"
	} else if a.cfg.AllowIncompleteInput {
		validation.Status = "development_incomplete"
	} else {
		validation.Status = "rejected"
	}
	a.inputValidation = validation

	if validation.Status == "rejected" {
		return fmt.Errorf(
			"analysis input is incomplete:\n  - %s\nrebuild the configured kernel, regenerate compile_commands.json, or use -allow-incomplete-input only for development",
			strings.Join(validation.Reasons, "\n  - "),
		)
	}
	if validation.Status == "development_incomplete" {
		fmt.Fprintf(
			os.Stderr,
			"warning: incomplete analysis input; final certifications are disabled:\n  - %s\n",
			strings.Join(validation.Reasons, "\n  - "),
		)
	}
	return nil
}

type kernelConfigStates struct {
	builtin  int
	modules  int
	disabled int
}

func countKernelConfigStates(path string) (kernelConfigStates, error) {
	file, err := os.Open(path)
	if err != nil {
		return kernelConfigStates{}, err
	}
	defer file.Close()

	states := kernelConfigStates{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "CONFIG_") &&
			strings.HasSuffix(line, "=y"):
			states.builtin++
		case strings.HasPrefix(line, "CONFIG_") &&
			strings.HasSuffix(line, "=m"):
			states.modules++
		case strings.HasPrefix(line, "# CONFIG_") &&
			strings.HasSuffix(line, " is not set"):
			states.disabled++
		}
	}
	if err := scanner.Err(); err != nil {
		return kernelConfigStates{}, err
	}
	return states, nil
}

func (a *Analyzer) classifySyscallAvailability(symbols map[string]byte) {
	for index := range a.syscalls {
		entry := &a.syscalls[index]
		if entry.Entry == "" || entry.Entry == "sys_ni_syscall" {
			entry.Availability = syscallAvailabilityUnavailableSlot
			if entry.AvailabilityReason == "" {
				entry.AvailabilityReason = "the x86-64 syscall table has no implementation entry for this ABI slot"
			}
			continue
		}
		symbol := linkedSyscallSymbol(*entry)
		entry.LinkedSymbol = symbol
		symbolType, ok := symbols[symbol]
		if !ok {
			entry.Availability = syscallAvailabilityUnresolvedLink
			entry.AvailabilityReason = "the expected syscall wrapper is absent from the completed build's System.map"
			continue
		}
		entry.LinkedSymbolType = string(symbolType)
		switch symbolType {
		case 'W', 'w':
			entry.Availability = syscallAvailabilityUnavailableConfig
			entry.AvailabilityReason = "the completed build links a weak conditional ENOSYS syscall stub"
		default:
			entry.Availability = syscallAvailabilityImplemented
			entry.AvailabilityReason = ""
		}
	}
}

func linkedSyscallSymbol(entry SyscallEntry) string {
	switch {
	case strings.HasPrefix(entry.Entry, "__x64_sys_"):
		return entry.Entry
	case strings.HasPrefix(entry.Entry, "sys_"):
		return "__x64_sys_" + strings.TrimPrefix(entry.Entry, "sys_")
	case strings.HasPrefix(entry.Entry, "compat_sys_"):
		return "__x64_compat_sys_" + strings.TrimPrefix(entry.Entry, "compat_sys_")
	default:
		return entry.Entry
	}
}

func loadSystemMap(path string) (map[string]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]byte)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || len(fields[1]) != 1 {
			continue
		}
		result[fields[2]] = fields[1][0]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func hashFileIfPresent(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func pathWithin(root, path string) bool {
	if root == "" || path == "" {
		return false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func compileCommandOutput(command CompileCommand) string {
	arguments, err := compileCommandArguments(command)
	if err != nil {
		return ""
	}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "-o" && index+1 < len(arguments) {
			output := arguments[index+1]
			if !filepath.IsAbs(output) {
				output = filepath.Join(command.Directory, output)
			}
			return filepath.Clean(output)
		}
		if strings.HasPrefix(argument, "-o") && len(argument) > 2 {
			output := strings.TrimPrefix(argument, "-o")
			if !filepath.IsAbs(output) {
				output = filepath.Join(command.Directory, output)
			}
			return filepath.Clean(output)
		}
	}
	return ""
}

type kbuildConfigFreshness struct {
	DependenciesChecked int
	NewerDependencies   []string
}

var kbuildConfigDependencyRE = regexp.MustCompile(
	`\$\(\s*wildcard\s+([^)]+)\)`,
)

func kbuildCommandFile(output string) string {
	return filepath.Join(
		filepath.Dir(output),
		"."+filepath.Base(output)+".cmd",
	)
}

func checkKbuildConfigFreshness(
	buildRoot string,
	output string,
	outputModTime time.Time,
) (kbuildConfigFreshness, error) {
	result := kbuildConfigFreshness{}
	raw, err := os.ReadFile(kbuildCommandFile(output))
	if err != nil {
		return result, err
	}

	dependencies := orderedSet(nil)
	for _, match := range kbuildConfigDependencyRE.FindAllStringSubmatch(string(raw), -1) {
		if len(match) != 2 {
			continue
		}
		for _, dependency := range strings.Fields(match[1]) {
			dependency = filepath.Clean(filepath.FromSlash(dependency))
			if dependency == "." ||
				!strings.HasPrefix(dependency, filepath.Join("include", "config")+string(filepath.Separator)) {
				continue
			}
			path := filepath.Join(buildRoot, dependency)
			if pathWithin(buildRoot, path) {
				dependencies.add(path)
			}
		}
	}

	for _, dependency := range dependencies.slice() {
		info, statErr := os.Stat(dependency)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return result, statErr
		}
		result.DependenciesChecked++
		if info.ModTime().After(outputModTime) {
			result.NewerDependencies = append(result.NewerDependencies, dependency)
		}
	}
	sort.Strings(result.NewerDependencies)
	return result, nil
}

func auxiliaryCompileCommand(command CompileCommand) bool {
	output := filepath.ToSlash(compileCommandOutput(command))
	for _, marker := range []string{
		"/arch/x86/purgatory/",
		"/arch/x86/boot/",
		"/tools/",
		"/scripts/",
	} {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

func compileCommandSemanticSignature(command CompileCommand) string {
	arguments, err := compileCommandArguments(command)
	if err != nil {
		return "invalid:" + command.Command
	}
	filtered := preprocessArguments(arguments)
	for index, argument := range filtered {
		if !filepath.IsAbs(argument) {
			continue
		}
		if clean := filepath.Clean(argument); clean == command.File {
			filtered[index] = "<SOURCE>"
		}
	}
	return command.Directory + "\x00" + strings.Join(filtered, "\x00")
}

func selectPrimaryCompileCommand(commands []CompileCommand) (CompileCommand, bool, int) {
	primary := make([]CompileCommand, 0, len(commands))
	auxiliaryCount := 0
	for _, command := range commands {
		if auxiliaryCompileCommand(command) {
			auxiliaryCount++
			continue
		}
		primary = append(primary, command)
	}
	if len(primary) == 0 {
		primary = append(primary, commands...)
	}
	sort.Slice(primary, func(left, right int) bool {
		leftOutput := compileCommandOutput(primary[left])
		rightOutput := compileCommandOutput(primary[right])
		if leftOutput != rightOutput {
			return leftOutput < rightOutput
		}
		return compileCommandSemanticSignature(primary[left]) <
			compileCommandSemanticSignature(primary[right])
	})
	signatures := orderedSet(nil)
	for _, command := range primary {
		signatures.add(compileCommandSemanticSignature(command))
	}
	return primary[0], len(signatures.items) > 1, auxiliaryCount
}
