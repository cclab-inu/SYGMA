package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	frontendCacheSchemaVersion = 5
	frontendCacheLogicVersion  = 14
)

type frontendCachePayload struct {
	SchemaVersion         int
	Fingerprint           string
	BuiltAt               string
	Functions             map[string]*FunctionInfo
	StructMembers         map[string][]string
	MemberAliases         map[string][][]string
	OperationTargets      map[string][]OperationTarget
	OperationLinks        map[string][]string
	OperationTables       map[string]*OperationTableInfo
	OperationTablesByName map[string][]string
	LLVMFailures          []string
	LSMWrapperHooks       map[string]string
	LSMHookNames          map[string]bool
	LSMMetadataBuilt      bool
}

func (a *Analyzer) frontendCacheFingerprint() (string, error) {
	hasher := sha256.New()
	initializeFrontendFingerprint(hasher, a, true)

	inputs, err := a.frontendFingerprintFiles()
	if err != nil {
		return "", fmt.Errorf("collect frontend cache inputs: %w", err)
	}
	legacyHasher := sha256.New()
	legacyAnalyzerLabel, legacyAnalyzerPath, legacyAvailable :=
		a.legacyFrontendAnalyzer()
	if legacyAvailable {
		initializeFrontendFingerprint(legacyHasher, a, false)
	}
	fmt.Fprintf(
		os.Stderr,
		"configured frontend cache: fingerprinting %d inputs\n",
		len(inputs),
	)
	inputSet := make(map[string]struct{}, len(inputs))
	union := append([]string(nil), inputs...)
	for _, path := range inputs {
		inputSet[path] = struct{}{}
	}
	if legacyAvailable {
		if _, ok := inputSet[legacyAnalyzerLabel]; !ok {
			union = append(union, legacyAnalyzerLabel)
		}
	}
	sort.Strings(union)
	for _, label := range union {
		actualPath := label
		hashers := make([]hash.Hash, 0, 2)
		if _, ok := inputSet[label]; ok {
			hashers = append(hashers, hasher)
		}
		if legacyAvailable {
			hashers = append(hashers, legacyHasher)
			if label == legacyAnalyzerLabel {
				actualPath = legacyAnalyzerPath
			}
		}
		if err := hashFrontendInputAs(hashers, label, actualPath); err != nil {
			return "", fmt.Errorf(
				"hash frontend cache input %s: %w",
				label,
				err,
			)
		}
	}
	fingerprint := fmt.Sprintf("%x", hasher.Sum(nil))
	if legacyAvailable {
		a.frontendCacheLegacyHash = fmt.Sprintf(
			"%x",
			legacyHasher.Sum(nil),
		)
		fmt.Fprintf(
			os.Stderr,
			"configured frontend cache: legacy fingerprint=%s\n",
			a.frontendCacheLegacyHash[:16],
		)
	}
	fmt.Fprintf(
		os.Stderr,
		"configured frontend cache: fingerprint=%s\n",
		fingerprint[:16],
	)
	return fingerprint, nil
}

func initializeFrontendFingerprint(
	hasher hash.Hash,
	a *Analyzer,
	includeLogicVersion bool,
) {
	writeFingerprintValue(
		hasher,
		"schema",
		fmt.Sprint(frontendCacheSchemaVersion),
	)
	if includeLogicVersion {
		writeFingerprintValue(
			hasher,
			"frontend-logic",
			fmt.Sprint(frontendCacheLogicVersion),
		)
	}
	writeFingerprintValue(hasher, "kernel-root", a.cfg.KernelRoot)
	writeFingerprintValue(hasher, "frontend", a.cfg.Frontend)
	writeFingerprintValue(hasher, "scan-all", fmt.Sprint(a.cfg.ScanAll))
	writeFingerprintValue(
		hasher,
		"llvm-verify",
		fmt.Sprint(a.cfg.LLVMVerify),
	)
	for _, name := range []string{
		"CPATH",
		"C_INCLUDE_PATH",
		"CPLUS_INCLUDE_PATH",
		"OBJC_INCLUDE_PATH",
	} {
		writeFingerprintValue(
			hasher,
			"environment:"+name,
			os.Getenv(name),
		)
	}
}

func (a *Analyzer) legacyFrontendAnalyzer() (string, string, bool) {
	executable, err := os.Executable()
	if err != nil || a.cfg.FrontendCache == "" {
		return "", "", false
	}
	backup := filepath.Join(
		filepath.Dir(a.cfg.FrontendCache),
		"configured-frontend-v2-analyzer",
	)
	info, err := os.Stat(backup)
	if err != nil || !info.Mode().IsRegular() {
		return "", "", false
	}
	return filepath.Clean(executable), backup, true
}

func (a *Analyzer) frontendFingerprintFiles() ([]string, error) {
	files := make(map[string]struct{})
	add := func(path string) {
		if strings.TrimSpace(path) == "" {
			return
		}
		files[filepath.Clean(path)] = struct{}{}
	}
	add(a.cfg.CompileDB)
	add(a.configPath)
	add(a.cfg.ClangExtractor)
	if a.cfg.Frontend == "hybrid" && a.cfg.LLVMVerify {
		add(a.cfg.LLVMVerifier)
	}
	for _, command := range a.compileUnits {
		arguments, err := compileCommandArguments(command)
		if err != nil || len(arguments) == 0 {
			continue
		}
		if compiler := resolveCommandExecutable(arguments[0], command.Directory); compiler != "" {
			add(compiler)
		}
	}

	if err := filepath.WalkDir(
		a.cfg.KernelRoot,
		func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path == a.cfg.KernelRoot {
					return nil
				}
				if shouldSkipDir(a.cfg.KernelRoot, path, a.cfg.ScanAll) ||
					entry.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".c", ".h", ".inc":
				add(path)
			}
			return nil
		},
	); err != nil {
		return nil, err
	}

	if a.cfg.CompileDB != "" {
		buildRoot := filepath.Dir(a.cfg.CompileDB)
		for _, relative := range []string{
			"include/generated",
			"include/config",
			"arch/x86/include/generated",
		} {
			root := filepath.Join(buildRoot, filepath.FromSlash(relative))
			if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			if err := filepath.WalkDir(
				root,
				func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if !entry.IsDir() {
						add(path)
					}
					return nil
				},
			); err != nil {
				return nil, err
			}
		}
	}
	for _, path := range a.configuredTranslationUnitPaths() {
		add(path)
	}

	result := make([]string, 0, len(files))
	for path := range files {
		if path == a.cfg.FrontendCache {
			continue
		}
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

func resolveCommandExecutable(command, directory string) string {
	if filepath.IsAbs(command) {
		return filepath.Clean(command)
	}
	if strings.ContainsRune(command, filepath.Separator) {
		return filepath.Clean(filepath.Join(directory, command))
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return absolute
}

func writeFingerprintValue(hasher hash.Hash, name, value string) {
	_, _ = io.WriteString(hasher, name)
	_, _ = io.WriteString(hasher, "\x00")
	_, _ = io.WriteString(hasher, value)
	_, _ = io.WriteString(hasher, "\x00")
}

func hashFrontendInputAs(
	hashers []hash.Hash,
	label, actualPath string,
) error {
	if len(hashers) == 0 {
		return nil
	}
	file, err := os.Open(actualPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	for _, hasher := range hashers {
		writeFingerprintValue(hasher, "file", filepath.Clean(label))
		writeFingerprintValue(hasher, "size", fmt.Sprint(info.Size()))
	}
	writers := make([]io.Writer, 0, len(hashers))
	for _, hasher := range hashers {
		writers = append(writers, hasher)
	}
	if _, err := io.Copy(io.MultiWriter(writers...), file); err != nil {
		return err
	}
	for _, hasher := range hashers {
		_, _ = io.WriteString(hasher, "\x00")
	}
	return nil
}

func (a *Analyzer) loadFrontendCache(fingerprint string) (bool, error) {
	file, err := os.Open(a.cfg.FrontendCache)
	if errors.Is(err, os.ErrNotExist) {
		a.frontendCacheStatus = "miss_not_found"
		fmt.Fprintf(
			os.Stderr,
			"configured frontend cache: miss (not found) path=%s\n",
			a.cfg.FrontendCache,
		)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open frontend cache: %w", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		a.frontendCacheStatus = "miss_invalid"
		fmt.Fprintf(os.Stderr, "configured frontend cache: ignoring invalid gzip: %v\n", err)
		return false, nil
	}
	defer reader.Close()

	var payload frontendCachePayload
	if err := gob.NewDecoder(reader).Decode(&payload); err != nil {
		a.frontendCacheStatus = "miss_invalid"
		fmt.Fprintf(os.Stderr, "configured frontend cache: ignoring invalid payload: %v\n", err)
		return false, nil
	}
	if payload.SchemaVersion != frontendCacheSchemaVersion {
		a.frontendCacheStatus = "miss_schema"
		fmt.Fprintf(
			os.Stderr,
			"configured frontend cache: miss (schema %d != %d)\n",
			payload.SchemaVersion,
			frontendCacheSchemaVersion,
		)
		return false, nil
	}
	legacyHit := payload.Fingerprint != fingerprint &&
		a.frontendCacheLegacyHash != "" &&
		payload.Fingerprint == a.frontendCacheLegacyHash
	if payload.Fingerprint != fingerprint && !legacyHit {
		a.frontendCacheStatus = "miss_fingerprint"
		fmt.Fprintln(os.Stderr, "configured frontend cache: miss (analysis inputs changed)")
		return false, nil
	}
	if len(payload.Functions) == 0 || !payload.LSMMetadataBuilt {
		a.frontendCacheStatus = "miss_incomplete"
		fmt.Fprintln(os.Stderr, "configured frontend cache: miss (payload incomplete)")
		return false, nil
	}

	a.functions = payload.Functions
	a.structMembers = nonNilStringSliceMap(payload.StructMembers)
	a.memberAliases = nonNilStringSliceSliceMap(payload.MemberAliases)
	a.operationTargets = nonNilOperationTargetMap(payload.OperationTargets)
	a.operationLinks = nonNilStringSliceMap(payload.OperationLinks)
	a.operationTables = nonNilOperationTableMap(payload.OperationTables)
	a.operationTablesByName = nonNilStringSliceMap(payload.OperationTablesByName)
	a.llvmFailures = append([]string(nil), payload.LLVMFailures...)
	a.lsmWrapperHooks = nonNilStringMap(payload.LSMWrapperHooks)
	a.lsmHookNames = nonNilBoolMap(payload.LSMHookNames)
	a.lsmMetadataBuilt = payload.LSMMetadataBuilt
	a.frontendCacheBuiltAt = payload.BuiltAt
	a.frontendCacheStatus = "hit"
	identityMigrated := a.normalizeCachedClangFunctionIdentities()
	if legacyHit {
		a.frontendCacheStatus = "hit_legacy"
		fmt.Fprintln(
			os.Stderr,
			"configured frontend cache: validated legacy analyzer fingerprint; migrating metadata only",
		)
	} else if identityMigrated {
		a.frontendCacheStatus = "hit_identity_migrated"
		fmt.Fprintln(
			os.Stderr,
			"configured frontend cache: canonicalized stale translation-unit-scoped inline identities",
		)
	}
	a.rebuildFunctionIndexes()
	if identityMigrated {
		a.resolveCalls()
	}
	a.resetAnalysisCachesAfterFrontendLoad()
	return true, nil
}

func (a *Analyzer) normalizeCachedClangFunctionIdentities() bool {
	changed := false
	oldIDs := make([]string, 0, len(a.functions))
	for id := range a.functions {
		oldIDs = append(oldIDs, id)
		if canonicalCachedClangFunctionID(id) != id {
			changed = true
		}
	}
	if !changed {
		return false
	}
	sort.Strings(oldIDs)
	for _, id := range oldIDs {
		function := a.functions[id]
		if function == nil {
			continue
		}
		function.ID = canonicalCachedClangFunctionID(function.ID)
		function.DisplayName = canonicalCachedClangDisplayName(
			function.DisplayName,
		)
		for callee, targets := range function.TypedCallees {
			for index := range targets {
				targets[index] = canonicalCachedClangFunctionID(
					targets[index],
				)
			}
			function.TypedCallees[callee] = uniqueStrings(targets)
		}
		for index := range function.DirectCallees {
			function.DirectCallees[index] =
				canonicalCachedClangFunctionID(
					function.DirectCallees[index],
				)
		}
		function.DirectCallees = uniqueStrings(function.DirectCallees)
		for siteIndex := range function.CallSites {
			site := &function.CallSites[siteIndex]
			for argumentIndex := range site.CallbackArguments {
				argument := &site.CallbackArguments[argumentIndex]
				for targetIndex := range argument.Targets {
					target := &argument.Targets[targetIndex]
					target.FunctionID =
						canonicalCachedClangFunctionID(
							target.FunctionID,
						)
				}
			}
		}
	}

	normalized := make(map[string]*FunctionInfo, len(a.functions))
	for _, oldID := range oldIDs {
		function := a.functions[oldID]
		if function == nil {
			continue
		}
		existing := normalized[function.ID]
		if existing == nil {
			normalized[function.ID] = function
			continue
		}
		existing.TranslationUnits = uniqueStrings(append(
			existing.TranslationUnits,
			function.TranslationUnits...,
		))
		existing.FrontendVariantCount +=
			max(1, function.FrontendVariantCount)
		existing.LLVMHookFacts = append(
			existing.LLVMHookFacts,
			function.LLVMHookFacts...,
		)
		existing.LLVMCallFacts = append(
			existing.LLVMCallFacts,
			function.LLVMCallFacts...,
		)
		existing.LLVMFunctionFacts = append(
			existing.LLVMFunctionFacts,
			function.LLVMFunctionFacts...,
		)
		if existing.Frontend == "clang-ast-cfg" &&
			function.Frontend == "clang-ast-cfg" {
			if sameClangFunctionVariant(existing, function) {
				mergeClangTypedTargets(existing, function)
			} else {
				mergeClangFunctionVariant(existing, function)
			}
		}
	}
	a.functions = normalized
	return true
}

func canonicalCachedClangFunctionID(id string) string {
	if index := strings.LastIndex(id, "@@tu="); index >= 0 {
		return id[:index]
	}
	return id
}

func canonicalCachedClangDisplayName(name string) string {
	index := strings.LastIndex(name, "@tu-")
	if index < 0 {
		return name
	}
	suffix := name[index+len("@tu-"):]
	if len(suffix) != 12 {
		return name
	}
	for _, value := range suffix {
		if value < '0' || value > '9' &&
			(value < 'a' || value > 'f') {
			return name
		}
	}
	return name[:index]
}

func (a *Analyzer) saveFrontendCache(fingerprint string) error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.FrontendCache), 0o755); err != nil {
		return fmt.Errorf("create frontend cache directory: %w", err)
	}
	builtAt := time.Now().UTC().Format(time.RFC3339)
	payload := frontendCachePayload{
		SchemaVersion:         frontendCacheSchemaVersion,
		Fingerprint:           fingerprint,
		BuiltAt:               builtAt,
		Functions:             a.functions,
		StructMembers:         a.structMembers,
		MemberAliases:         a.memberAliases,
		OperationTargets:      a.operationTargets,
		OperationLinks:        a.operationLinks,
		OperationTables:       a.operationTables,
		OperationTablesByName: a.operationTablesByName,
		LLVMFailures:          append([]string(nil), a.llvmFailures...),
		LSMWrapperHooks:       a.lsmWrapperHooks,
		LSMHookNames:          a.lsmHookNames,
		LSMMetadataBuilt:      a.lsmMetadataBuilt,
	}
	temp, err := os.CreateTemp(
		filepath.Dir(a.cfg.FrontendCache),
		".configured-frontend-*.tmp",
	)
	if err != nil {
		return fmt.Errorf("create frontend cache temp file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	writer, err := gzip.NewWriterLevel(temp, gzip.BestSpeed)
	if err != nil {
		return fmt.Errorf("create frontend cache compressor: %w", err)
	}
	fmt.Fprintf(
		os.Stderr,
		"configured frontend cache: writing %d functions to %s\n",
		len(a.functions),
		a.cfg.FrontendCache,
	)
	if err := gob.NewEncoder(writer).Encode(payload); err != nil {
		_ = writer.Close()
		return fmt.Errorf("encode frontend cache: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close frontend cache compressor: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync frontend cache: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close frontend cache: %w", err)
	}
	if err := os.Rename(tempPath, a.cfg.FrontendCache); err != nil {
		return fmt.Errorf("replace frontend cache: %w", err)
	}
	committed = true
	a.frontendCacheBuiltAt = builtAt
	if a.frontendCacheStatus == "rebuild_requested" {
		a.frontendCacheStatus = "rebuilt"
	} else if a.frontendCacheStatus == "hit_legacy" {
		a.frontendCacheStatus = "migrated"
	} else if a.frontendCacheStatus == "hit_identity_migrated" {
		a.frontendCacheStatus = "migrated_identity"
	} else {
		a.frontendCacheStatus = "stored"
	}
	fmt.Fprintln(os.Stderr, "configured frontend cache: stored")
	return nil
}

func nonNilStringMap(value map[string]string) map[string]string {
	if value == nil {
		return make(map[string]string)
	}
	return value
}

func nonNilBoolMap(value map[string]bool) map[string]bool {
	if value == nil {
		return make(map[string]bool)
	}
	return value
}

func nonNilStringSliceMap(value map[string][]string) map[string][]string {
	if value == nil {
		return make(map[string][]string)
	}
	return value
}

func nonNilStringSliceSliceMap(value map[string][][]string) map[string][][]string {
	if value == nil {
		return make(map[string][][]string)
	}
	return value
}

func nonNilOperationTargetMap(
	value map[string][]OperationTarget,
) map[string][]OperationTarget {
	if value == nil {
		return make(map[string][]OperationTarget)
	}
	return value
}

func nonNilOperationTableMap(
	value map[string]*OperationTableInfo,
) map[string]*OperationTableInfo {
	if value == nil {
		return make(map[string]*OperationTableInfo)
	}
	return value
}
