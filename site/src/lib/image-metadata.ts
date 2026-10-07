export interface ImageMetadata {
  description: string;
  useCases: string[];
  dockerfileExample: string;
  ubiExample: string;
  nixExample: string;
  layeringExample: string;
}

// Capitalize helper
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

// Generate Nix attribute name matching the overlays in flake.nix
function getNixAttr(langId: string, version: string): string {
  if (langId === 'core') return 'clearcuttCore';
  return `clearcutt${cap(langId)}${version.replace(/\./g, '')}`;
}

function githubRepoFromImageRef(fullName: string): string {
  const parts = fullName.replace(/^ghcr\.io\//, '').split('/');
  if (parts.length >= 3 && parts[0] && parts[1]) {
    return `${parts[0]}/${parts[1]}`;
  }
  return 'northcutted/clearcutt-verify';
}

export function getImageMetadata(
  languageId: string,
  languageVersion: string,
  tierId: 'dev' | 'slim' | 'distroless',
  fullName: string,
  tag: string
): ImageMetadata {
  const devImage = `${fullName}:${tag}-dev`;
  const runtimeImage = `${fullName}:${tag}-${tierId}`;
  const nixAttr = getNixAttr(languageId, languageVersion);
  const flakeRef = `github:${githubRepoFromImageRef(fullName)}/${tag}?dir=core`;

  // 1. GENERATE TIER GUARANTEES AND DESCRIPTION COPY
  let description = '';
  let useCases: string[] = [];

  switch (languageId) {
    case 'core':
      if (tierId === 'dev') {
        description = `This Core builder image provides a fully equipped development and compiler environment. It packages standard system libraries, compiler tools (gcc, make), headers, CA certificates, and shell debugging utilities natively in a CVE-remediated workspace.`;
        useCases = [
          'Compiling customized system libraries or compiling C/C++ extensions from source',
          'Executing high-privilege diagnostics, container debugging, and cluster verification tasks',
          'Running CI/CD runners that require access to git, curl, and active shell utilities'
        ];
      } else if (tierId === 'slim') {
        description = `This Core runtime image provides a lightweight, minimalist base. It packages system libraries (glibc), timezone databases, SSL certificates, and a restricted BusyBox shell, maintaining full remediation against critical CVEs.`;
        useCases = [
          'Lightweight base for pre-compiled static and dynamic binaries',
          'Running custom orchestration shell scripts and system hooks in staging/production',
          'Hosting basic diagnostics utilities that require limited interactive terminal tools'
        ];
      } else {
        description = `This Core distroless image is the smallest Core runtime tier. It excludes shells, coreutils, and package managers, providing glibc, CA certificates, and timezone registries with a reduced utility surface.`;
        useCases = [
          'Hosting pre-compiled statically-linked Go, Rust, or C/C++ microservices',
          'Production deployments that need a shell-free base with current vulnerability evidence',
          'Secure runtime hosting for highly sensitive data ingestion and messaging layers'
        ];
      }
      break;

    case 'java':
      if (tierId === 'dev') {
        description = `This Java Development Kit (JDK) image provides a comprehensive Zulu OpenJDK ${languageVersion} compilation and troubleshooting environment. It contains complete profiling, diagnostic, and build toolchains.`;
        useCases = [
          'Compiling complex Java/Kotlin applications using Maven or Gradle wrappers',
          'Running JVM diagnostic pipelines (jmap, jstack, jcmd) inside dev containers',
          'Executing unit and integration testing pipelines with full shell access'
        ];
      } else if (tierId === 'slim') {
        description = `This Java Runtime Environment (JRE) image delivers a Zulu OpenJDK JRE ${languageVersion} environment equipped with a restricted BusyBox debugging shell. It is designed for lightweight hosting with basic shell inspection capabilities.`;
        useCases = [
          'Deploying standard enterprise web applications (Spring Boot, Quarkus, Micronaut)',
          'Running microservices that require runtime hooks or staging environment diagnostics',
          'Hosting modular JRE processes with optimized memory configurations'
        ];
      } else {
        description = `This Java Runtime Environment (JRE) distroless image delivers a hardened, shell-less Zulu JRE ${languageVersion} runtime. It strips away shell and package-manager utilities while preserving a standard JVM runtime boundary.`;
        useCases = [
          'Production hosting for sensitive financial or medical Java APIs',
          'Deploying optimized Spring Boot microservices with minimal OCI layer overhead',
          'Strict environments that require shell-free runtime images'
        ];
      }
      break;

    case 'node':
      if (tierId === 'dev') {
        description = `This Node.js developer image delivers Node.js ${languageVersion}, npm, yarn, corepack, and system compilers. It enables native dependency compilation (node-gyp) in a catalog-scanned workspace.`;
        useCases = [
          'Building deployable frontend bundles (Vite, Next.js, Nuxt) from source',
          'Compiling native C-bindings (node-gyp, bcrypt, sharp, sqlite) cleanly',
          'Running testing tools and linting engines inside sandboxed container stages'
        ];
      } else if (tierId === 'slim') {
        description = `This Node.js runtime image delivers a standard Node.js ${languageVersion} interpreter alongside a restricted BusyBox shell, enabling lightweight hosting with basic terminal diagnostic utilities.`;
        useCases = [
          'Deploying standard REST APIs and Webhook microservices (Express, Fastify, NestJS)',
          'Running staging or development Node servers that require log shipping and shell hooks',
          'Hosting lightweight server-side rendering (SSR) applications with limited OS access'
        ];
      } else {
        description = `This Node.js distroless image packages a hardened, shell-less Node.js ${languageVersion} engine. It excludes package managers (npm, yarn) and shell layers while keeping the Node runtime directly executable.`;
        useCases = [
          'Hosting backend microservices in shell-free runtime environments',
          'Deploying performance-sensitive REST or gRPC APIs with minimal layer counts',
          'Secure runtime hosting that resists common shell-spawn exploit paths'
        ];
      }
      break;

    case 'python':
      if (tierId === 'dev') {
        description = `This Python developer image offers Python ${languageVersion}, pip, virtualenv, and GNU compiler headers. It is optimized for installing and building scientific packages and C-extensions from source.`;
        useCases = [
          'Compiling heavy scientific and machine learning dependencies (NumPy, SciPy, Pandas, PyTorch)',
          'Running full pip package installation, wheel compilation, and testing frameworks',
          'Running automated task execution scripts in dev containers with full compiler access'
        ];
      } else if (tierId === 'slim') {
        description = `This Python runtime image packages the Python ${languageVersion} interpreter and standard library next to a restricted BusyBox shell, ideal for standard hosting requiring minor shell controls.`;
        useCases = [
          'Deploying lightweight web servers and asynchronous backends (FastAPI, Django, Uvicorn)',
          'Executing cron-based data synchronization or system administration scripts',
          'Hosting microservices that require custom OS entrypoint scripts and diagnostic access'
        ];
      } else {
        description = `This Python distroless image packages a hardened, shell-less Python ${languageVersion} runtime. By excluding pip, setuptools, and shell binaries, it delivers a secure environment with an extremely small attack surface.`;
        useCases = [
          'Hosting production-grade FastAPI and Django APIs in secure OCI environments',
          'Deploying pre-packaged machine learning models (scikit-learn, TensorFlow) in locked-down clusters',
          'Secure background worker execution requiring a shell-free runtime surface'
        ];
      }
      break;

    case 'go':
      if (tierId === 'dev') {
        description = `This Go developer image packages the Go ${languageVersion} compiler toolchain, git, make, and build essentials. It is designed to act as a highly performant and secure multi-stage compilation stage.`;
        useCases = [
          'Compiling complex Go binaries from source code with native caching structures',
          'Running go test pipelines, benchmark suites, and static analysis linters',
          'Creating automated OCI image build pipelines within secure development environments'
        ];
      } else if (tierId === 'slim') {
        description = `This Go runtime image is equipped with a restricted BusyBox debugging shell. It is designed to act as a lightweight runtime host for compiled Go applications that require basic terminal inspection.`;
        useCases = [
          'Running Go microservices in staging environments where active log tracing is required',
          'Deploying network agents or tooling that need limited busybox shell diagnostics',
          'Executing Go automation scripts with configurable network or OS system calls'
        ];
      } else {
        description = `This Go distroless image offers a hardened OCI container base with no shell and no utility layer. It is optimized for hosting statically and dynamically linked Go binaries.`;
        useCases = [
          'Hardened production hosting of highly sensitive Go REST and gRPC microservices',
          'Deploying edge containers and cloud-native agents with a minimal storage footprint',
          'Reducing common shell-spawn exploit paths by omitting shell utilities'
        ];
      }
      break;

    case 'dotnet':
      if (tierId === 'dev') {
        description = `This .NET SDK developer image delivers .NET ${languageVersion} SDK, MSBuild, NuGet, and complete compiler pipelines. It is optimized for source compilation and unit testing inside OCI environments.`;
        useCases = [
          'Compiling, packing, and publishing C# and F# enterprise applications from source code',
          'Running MSBuild and dotnet test execution stages inside automated pipelines',
          'Building C# microservices with isolated NuPkg package restores'
        ];
      } else if (tierId === 'slim') {
        description = `This .NET ASP.NET runtime image delivers the core runtime engine next to a restricted BusyBox shell, ideal for standard enterprise deployments requiring lightweight terminal access.`;
        useCases = [
          'Deploying C# Web APIs and background services (ASP.NET Core, gRPC, Worker Services)',
          'Running staging deployments that require shell inspection or diagnostics',
          'Hosting lightweight server-side .NET processes with limited operating system dependencies'
        ];
      } else {
        description = `This .NET ASP.NET runtime distroless image delivers a hardened, shell-less enterprise hosting container. It minimizes the runtime utility surface around the C# runtime stack.`;
        useCases = [
          'Hardened production hosting of C# microservices, financial APIs, and enterprise backends',
          'Deploying ASP.NET Core apps with strict regulatory requirements (PCI-DSS, HIPAA)',
          'Strict clusters looking to eliminate container-breakout shell utilities'
        ];
      }
      break;

    case 'rust':
      if (tierId === 'dev') {
        description = `This Rust developer image delivers the Rust ${languageVersion} compiler (rustc, cargo) and compile-time dependencies. It is optimized to serve as a fast and secure OCI compilation pipeline.`;
        useCases = [
          'Compiling multi-platform Cargo crates with optimized build cache systems',
          'Running cargo clippy, cargo test, and static analyzer engines',
          'Developing system tools natively inside catalog-scanned OCI pipelines'
        ];
      } else if (tierId === 'slim') {
        description = `This Rust runtime image delivers standard system libraries and a restricted BusyBox shell, ideal for hosting pre-built Rust binaries that require limited terminal troubleshooting utilities.`;
        useCases = [
          'Hosting lightweight compiled Rust services requiring staging terminal log triggers',
          'Running network diagnostics or system utilities compiled natively in Rust',
          'Staging environments requiring active file system monitoring and shell utilities'
        ];
      } else {
        description = `This Rust distroless image delivers a highly hardened, shell-less base container containing only glibc and CA trust anchors. It is optimized for hosting statically and dynamically compiled Rust microservices.`;
        useCases = [
          'Production deployments of ultra-high-performance Rust web servers and gRPC APIs',
          'Deploying resource-constrained edge-computing nodes and embedded container workloads',
          'Reducing common shell-injection paths in minimal runtime environments'
        ];
      }
      break;

    default: // cc (C/C++) and other fallbacks
      if (tierId === 'dev') {
        description = `This C/C++ developer image contains the GCC compiler, G++, Make, CMake, and standard headers. It provides a robust, CVE-remediated workspace for building system libraries from source.`;
        useCases = [
          'Compiling C/C++ applications, system agents, or extensions using GNU/Makefile pipelines',
          'Building high-performance native binaries with full access to standard compilation headers',
          'Executing unit testing suites and memory-leak diagnostic checks inside build systems'
        ];
      } else if (tierId === 'slim') {
        description = `This C/C++ runtime image packages standard libraries (glibc) and a restricted BusyBox shell, ideal for hosting compiled binaries with limited debugging capabilities.`;
        useCases = [
          'Staging runtime for compiled C/C++ binaries that require terminal checkups',
          'Executing lightweight daemon processes requiring minor OS hook scripts',
          'Deploying legacy system binaries in a containerized, CVE-remediated staging sandbox'
        ];
      } else {
        description = `This C/C++ distroless base provides a hardened OCI workspace with no shells. It is designed to host statically and dynamically compiled C/C++ binaries with a minimal runtime surface.`;
        useCases = [
          'Production-oriented hosting of pre-compiled C/C++ server nodes and daemons',
          'Edge deployments looking for minimal container footprint and current vulnerability evidence',
          'Executing compiled network filters and low-level controllers in hardened environments'
        ];
      }
      break;
  }

  // 2. GENERATE Bespoke CODE BLUEPRINTS
  let dockerfileExample = '';
  let nixExample = '';
  let layeringExample = '';

  // Generate dynamic, real-world examples based on language & tier
  switch (languageId) {
    case 'python':
      dockerfileExample = `# Stage 1: Build virtualenv using the dev builder image
FROM ${devImage} AS builder
WORKDIR /app

# Set up virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Hardened runner stage (distroless or slim JRE/Python runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy virtualenv and application code
COPY --from=builder /opt/venv /opt/venv
COPY . .

# Set environment and execute as secure non-root operator
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER 10001:10001
CMD ["python", "app.py"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated Python interpreter:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or import inside your local flake.nix devShell overlay:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Build a custom OCI image by layering extra packages in your Nix config
pkgs.dockerTools.buildImage {
  name = "custom-python-service";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;
  
  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      pkgs.ffmpeg           # Layer in extra tools declaratively
      python-application    # Include your compiled python build
    ];
    pathsToLink = [ "/bin" "/lib" ];
  };

  config = {
    Cmd = [ "/bin/app" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'node':
      dockerfileExample = `# Stage 1: Install dependencies and compile project using dev builder
FROM ${devImage} AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build --if-present

# Stage 2: Hardened runner stage (distroless or slim Node runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy built package and production dependencies
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Run as secure non-root operator
USER 10001:10001
ENV NODE_ENV=production
CMD ["node", "dist/index.js"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated Node.js engine:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix environment:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Layer a custom Node app into a secure OCI image declaratively in Nix
pkgs.dockerTools.buildImage {
  name = "custom-node-api";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      pkgs.graphicsmagick  # Layer in native dependency declaratively
      node-application     # Include your Node.js distribution env
    ];
    pathsToLink = [ "/bin" "/lib" ];
  };

  config = {
    Cmd = [ "/bin/api" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'java':
      dockerfileExample = `# Stage 1: Build the Maven application inside Java JDK dev builder
FROM ${devImage} AS builder
WORKDIR /app

COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Hardened runner stage (distroless or slim Java JRE runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy JRE-optimized JAR file
COPY --from=builder /app/target/*.jar ./app.jar

# Run JRE application as secure non-root operator
USER 10001:10001
CMD ["java", "-jar", "app.jar"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated Zulu JDK:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Layer a custom JAR application declaratively in your Nix configuration
pkgs.dockerTools.buildImage {
  name = "custom-java-microservice";
  tag = "latest";
  
  # Layer on top of ClearCutt's JRE base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      pkgs.zlib           # Layer in native dynamic libraries
      java-app-package    # Include your packaged JAR launcher
    ];
    pathsToLink = [ "/bin" "/lib" ];
  };

  config = {
    Cmd = [ "/bin/java-app" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'go':
      dockerfileExample = `# Stage 1: Compile statically-linked Go binary in the Go dev builder
FROM ${devImage} AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o main .

# Stage 2: Hardened runner stage (distroless or slim OCI runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy statically-linked compiled Go executable
COPY --from=builder /app/main ./main

# Run Go application as secure non-root operator
USER 10001:10001
CMD ["./main"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated Go toolchain:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix environment:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Build a Go custom image declaratively by compiling via Nix and packaging
pkgs.dockerTools.buildImage {
  name = "custom-go-server";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      go-application-compiled  # Pure Go binary compiled declaratively via Nix
    ];
    pathsToLink = [ "/bin" ];
  };

  config = {
    Cmd = [ "/bin/server" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'dotnet':
      dockerfileExample = `# Stage 1: Build and publish .NET assembly in SDK dev builder
FROM ${devImage} AS builder
WORKDIR /app

COPY *.csproj ./
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release -o out --no-restore

# Stage 2: Hardened runner stage (distroless or slim ASP.NET runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy published assemblies
COPY --from=builder /app/out ./

# Set environment and run as secure non-root operator
USER 10001:10001
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
CMD ["dotnet", "MyDotnetApp.dll"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated .NET SDK:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix environment:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Layer a .NET runtime release into a custom OCI image declaratively in Nix
pkgs.dockerTools.buildImage {
  name = "custom-dotnet-service";
  tag = "latest";
  
  # Layer on top of ClearCutt's runtime base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      dotnet-published-package # Monopackage compiled cleanly via Nix env
    ];
    pathsToLink = [ "/bin" ];
  };

  config = {
    Cmd = [ "/bin/dotnet-service" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'rust':
      dockerfileExample = `# Stage 1: Build optimized Rust binary in dev cargo compiler builder
FROM ${devImage} AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
# Create dummy main to cache dependency compilation
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release

COPY . .
RUN touch src/main.rs && cargo build --release

# Stage 2: Hardened runner stage (distroless or slim OCI runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy compiled Rust executable
COPY --from=builder /app/target/release/myapp ./myapp

# Run Rust application as secure non-root operator
USER 10001:10001
CMD ["./myapp"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated Rust compiler:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Build a Rust OCI container declaratively via Nix
pkgs.dockerTools.buildImage {
  name = "custom-rust-app";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      rust-compiled-binary   # Highly optimized Rust package compiled cleanly
    ];
    pathsToLink = [ "/bin" ];
  };

  config = {
    Cmd = [ "/bin/rust-app" ];
    User = "10001:10001";
  };
}`;
      break;

    case 'core':
      dockerfileExample = `# Best-practice container compilation pattern using the dev builder image
FROM ${devImage} AS builder
WORKDIR /app
COPY . .
RUN make build # Compile static system utilities

# Hardened runner stage (distroless or slim OCI runtime)
FROM ${runtimeImage}
WORKDIR /app
COPY --from=builder /app/bin/* ./bin/

# Execute binary as secure non-root operator
USER 10001:10001
CMD ["./bin/app"]`;

      nixExample = `# Enter a local development shell with core packages and overlays pre-loaded:
$ nix shell ${flakeRef}#${nixAttr}

# Or declare in a custom local flake.nix:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Declare a custom container assembly dynamically layered in Nix
pkgs.dockerTools.buildImage {
  name = "custom-system-daemon";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      pkgs.openssl          # Layer in CVE-remediated cryptography libraries
      custom-daemon-binary  # Include custom daemon compiled natively
    ];
    pathsToLink = [ "/bin" "/lib" ];
  };

  config = {
    Cmd = [ "/bin/daemon" ];
    User = "10001:10001";
  };
}`;
      break;

    default: // cc (C/C++) and fallbacks
      dockerfileExample = `# Stage 1: Build the C/C++ application inside GCC dev builder
FROM ${devImage} AS builder
WORKDIR /app

COPY CMakeLists.txt .
COPY src ./src
RUN cmake . && make

# Stage 2: Hardened runner stage (distroless or slim JRE/runtime)
FROM ${runtimeImage}
WORKDIR /app

# Copy compiled executable
COPY --from=builder /app/bin/myapp ./myapp

# Run C/C++ application as secure non-root operator
USER 10001:10001
CMD ["./myapp"]`;

      nixExample = `# Run an interactive local dev shell with the exact same remediated GCC environment:
$ nix shell ${flakeRef}#${nixAttr}-native

# Or declare inside your local flake.nix:
{
  inputs.clearcutt.url = "${flakeRef}";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      buildInputs = [ pkgs.${nixAttr} ];
    };
  };
}`;

      layeringExample = `# Build a C/C++ custom image declaratively by compiling via Nix and packaging
pkgs.dockerTools.buildImage {
  name = "custom-cpp-daemon";
  tag = "latest";
  
  # Layer on top of ClearCutt's base
  fromImage = clearcutt-base-image;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      pkgs.zlib             # Layer in extra dynamically-linked libraries
      cpp-application       # Pure C/C++ binary compiled declaratively via Nix
    ];
    pathsToLink = [ "/bin" "/lib" ];
  };

  config = {
    Cmd = [ "/bin/daemon" ];
    User = "10001:10001";
  };
}`;
      break;
  }

  const runtimeId = languageId === 'core' ? 'coreLTS' : `${languageId}${languageVersion}`;
  const ubiExample = `{
  description = "ClearCutt ${runtimeId} grafted onto a mandated base";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    clearcutt.url = "${flakeRef}";
  };

  outputs = { self, nixpkgs, clearcutt }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      mandatedBase = pkgs.dockerTools.pullImage {
        imageName = "registry.access.redhat.com/ubi9/ubi-minimal";
        imageDigest = "sha256:REPLACE_WITH_PINNED_BASE_DIGEST";
        sha256 = "sha256-REPLACE_WITH_NIX_PREFETCH_DOCKER_HASH";
      };
    in {
      packages.\${system}.overlayImage = clearcutt.lib.graftOntoBase {
        inherit system;
        fromImage = mandatedBase;
        runtime = "${runtimeId}";
        tier = "${tierId}";
        name = "acme-${runtimeId}-ubi";
        tag = "${tag}";
      };
    };
}

# Build: nix build .#packages.x86_64-linux.overlayImage
# Then prove the grafted runtime is byte-identical to the native runtime:
# clearcutt-verify overlay verify \\
#   --runtime-archive clearcutt-${runtimeId}.tar \\
#   --grafted-archive result \\
#   --runtime-ref ${runtimeImage}@sha256:... \\
#   --grafted-ref ghcr.io/acme/${runtimeId}-ubi:${tag}@sha256:... \\
#   --target ${runtimeId}-${tierId} \\
#   --output-predicate`;

  return {
    description,
    useCases,
    dockerfileExample,
    ubiExample,
    nixExample,
    layeringExample
  };
}
