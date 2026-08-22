// cmd/main.go
//  main.go -    Config Operator  Policy Agent

package main

import (
	"flag"
	"os"

	_ "crypto/sha256"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1 "example.org/sygma/operator/api/v1"
	"example.org/sygma/operator/internal/controller"
	"example.org/sygma/operator/pkg/bpf"
	"example.org/sygma/operator/pkg/storage"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var redisAddr string
	var redisPassword string
	var redisDB int
	var runMode string // ⭐ NEW:

	flag.StringVar(&runMode, "mode", "all", "Run mode: 'config' (Config Operator), 'agent' (Policy Agent), 'all' (both)")
	flag.StringVar(&redisPassword, "redis-password", "", "Redis password")
	flag.IntVar(&redisDB, "redis-db", 0, "Redis database number")
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&redisAddr, "redis-addr", "localhost:30379", "Redis address")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info("Starting SYGMA Operator", "mode", runMode)

	// ⭐ Agent   NODE_NAME
	nodeName := os.Getenv("NODE_NAME")
	if runMode == "agent" && nodeName == "" {
		setupLog.Error(nil, "NODE_NAME environment variable required for agent mode")
		os.Exit(1)
	}

	config := ctrl.GetConfigOrDie()

	// ⭐ Agent  Leader Election
	if runMode == "agent" {
		enableLeaderElection = false
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sygma-operator.security.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Redis  Storage  ()
	redisClient := storage.NewRedisClient(redisAddr, redisPassword, redisDB)
	setupLog.Info("Redis client initialized", "address", redisAddr)

	syscallManager := storage.NewSyscallGraphManager(redisClient)
	setupLog.Info("Syscall graph manager initialized")

	// ========== CONFIG MODE ==========
	if runMode == "config" || runMode == "all" {
		setupLog.Info("Setting up SYGMAConfig controller (Config Operator mode)")

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			setupLog.Error(err, "unable to create clientset")
			os.Exit(1)
		}

		// ⭐ Config Operator eBPF
		var configBPFManager *bpf.Manager
		if runMode == "config" {
			// config   BPF Manager
			configBPFManager, err = bpf.NewManager()
			if err != nil {
				setupLog.Error(err, "unable to create BPF manager for config operator")
				os.Exit(1)
			}
			setupLog.Info("✅ BPF Manager initialized for Config Operator")
		} else {
			// all   (best effort)
			configBPFManager, err = bpf.NewManager()
			if err != nil {
				setupLog.Info("⚠️ BPF manager not available for config mode, dynamic analysis disabled")
				configBPFManager = nil
			} else {
				setupLog.Info("✅ BPF Manager initialized for Config Operator")
			}
		}

		if err = (&controller.SYGMAConfigReconciler{
			Client:         mgr.GetClient(),
			Scheme:         mgr.GetScheme(),
			Config:         config,
			Clientset:      clientset,
			RedisClient:    redisClient,
			SyscallManager: syscallManager,
			BPFManager:     configBPFManager, // ✅ BPF Manager
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "SYGMAConfig")
			os.Exit(1)
		}
		setupLog.Info("✅ SYGMAConfig controller registered")
	}

	// ========== AGENT MODE ==========
	if runMode == "agent" || runMode == "all" {
		setupLog.Info("Setting up SYGMAPolicy controller (Policy Agent mode)", "node", nodeName)

		// Agent BPF Manager
		bpfManager, err := bpf.NewManager()
		if err != nil {
			setupLog.Error(err, "unable to create BPF manager")
			if runMode == "agent" {
				// Agent  BPF
				os.Exit(1)
			}
			// all
			setupLog.Info("⚠️ Continuing without BPF manager - policy enforcement disabled")
			bpfManager = nil
		} else {
			setupLog.Info("✅ BPF Manager initialized")
		}

		// ⭐  SYGMAPolicyReconciler
		if err = (&controller.SYGMAPolicyReconciler{
			Client:         mgr.GetClient(),
			Scheme:         mgr.GetScheme(),
			RedisClient:    redisClient,
			SyscallManager: syscallManager,
			BPFManager:     bpfManager,
			NodeName:       nodeName, // ⭐ NEW:
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "SYGMAPolicy")
			os.Exit(1)
		}
		setupLog.Info("✅ SYGMAPolicy controller registered")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager", "mode", runMode)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
