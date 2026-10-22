;; GNU Guix reproducible package & manifest definition for manta
;; Build Docker image:
;;   guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm

(use-modules (guix packages)
             (guix gexp)
             (guix build-system gnu)
             (guix build-system trivial)
             ((guix licenses) #:prefix license:)
             (gnu packages linux)
             (gnu packages curl)
             (gnu packages certs)
             (gnu packages base)
             (gnu packages bash)
             (gnu packages rust)
             (gnu packages commencement))

;; 1. Source-built package definition (compiles all 3 Rust crates from source inside Guix sandbox)
(define-public manta-from-source
  (package
    (name "manta-from-source")
    (version "0.1.0")
    (source (local-file "." "manta-checkout"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (not (or (string-contains file "/target")
                                             (string-contains file "/prebuilt")
                                             (string-contains file "/.git"))))))
    (build-system gnu-build-system)
    (native-inputs
     (list rust
           (list rust "cargo")
           gcc-toolchain))
    (arguments
     (list
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (replace 'build
            (lambda _
              (setenv "HOME" "/tmp")
              (invoke "cargo" "build" "--release" "--offline")))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (bin (string-append out "/bin"))
                     (etc (string-append out "/etc"))
                     (caddy-etc (string-append etc "/caddy")))
                (mkdir-p bin)
                (mkdir-p caddy-etc)
                (for-each
                 (lambda (prog)
                   (install-file (string-append "target/release/" prog) bin))
                 '("manta-init"
                   "manta-config"
                   "manta-health"))
                (install-file "assets/default-Caddyfile" caddy-etc)
                (install-file "assets/cloudflare-ips.txt" caddy-etc)))))))
    (home-page "https://github.com/UberMetroid/manta")
    (synopsis "Zero-dependency Rust Caddy v2 supervisor and CrowdSec AppSec WAF validator")
    (description
     "Manta is a hardened Caddy v2 Reverse Proxy & CrowdSec AppSec WAF Bouncer appliance for Emby, Jellyfin, Seerr, and the *arr media stack built with GNU Guix and 3 zero-dependency Rust binaries.")
    (license license:expat)))

;; 2. Fast packaging of the 3 statically-linked Rust binaries + static Caddy v2.11.7 + /etc configuration
(define-public manta-suite
  (package
    (name "manta-suite")
    (version "0.1.0")
    (source (local-file "." "manta-static"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (or (string=? file ".")
                                        (string-contains file "/prebuilt")
                                        (string-contains file "/assets")))))
    (build-system trivial-build-system)
    (native-inputs (list coreutils))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((src #$source)
                 (out #$output)
                 (bin (string-append out "/bin"))
                 (etc (string-append out "/etc"))
                 (caddy-etc (string-append etc "/caddy")))
            (mkdir-p bin)
            (mkdir-p caddy-etc)
            (for-each
             (lambda (prog)
               (let ((src-bin (string-append src "/prebuilt/" prog))
                     (dst-bin (string-append bin "/" prog)))
                 (copy-file src-bin dst-bin)
                 (chmod dst-bin #o755)))
             '("manta-init"
               "manta-config"
               "manta-health"
               "caddy"))
            (copy-file (string-append src "/assets/default-Caddyfile")
                       (string-append caddy-etc "/default-Caddyfile"))
            (copy-file (string-append src "/assets/cloudflare-ips.txt")
                       (string-append caddy-etc "/cloudflare-ips.txt"))
            (call-with-output-file (string-append etc "/passwd")
              (lambda (port)
                (display "root:x:0:0:root:/root:/bin/sh\nnobody:x:99:100:Unraid Nobody:/config:/bin/sh\n" port)))
            (call-with-output-file (string-append etc "/group")
              (lambda (port)
                (display "root:x:0:\nusers:x:100:nobody\n" port)))
            (call-with-output-file (string-append etc "/nsswitch.conf")
              (lambda (port)
                (display "hosts: files dns\n" port)))))))
    (home-page "https://github.com/UberMetroid/manta")
    (synopsis "Zero-dependency static Rust Caddy v2 supervisor and CrowdSec AppSec WAF appliance")
    (description
     "Manta is a hardened Caddy v2 Reverse Proxy & CrowdSec AppSec WAF Bouncer appliance built with GNU Guix, static Caddy v2.11.7 (crowdsec http/appsec/layer4), and 3 zero-dependency static Rust binaries (manta-init, manta-config, manta-health).")
    (license license:expat)))

(concatenate-manifests
 (list (packages->manifest (list manta-suite))
       (specifications->manifest
        '("util-linux"
          "curl"
          "nss-certs"
          "coreutils"
          "bash-minimal"))))
