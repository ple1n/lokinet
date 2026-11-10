{
  description = "Lokinet embedded library and Rust bindings";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lokinetEmbedded = pkgs.stdenv.mkDerivation {
            pname = "lokinet-embedded";
            version = "0.9.16";
            src = ./.;
            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.curl
              pkgs.libuv
              pkgs.libsodium
              pkgs.nettle
              pkgs.unbound
              pkgs.libxcrypt
              pkgs.zstd
              pkgs.zeromq
            ];
            cmakeFlags = [
              "-DBUILD_DAEMON=OFF"
              "-DBUILD_LIBLOKINET=ON"
              "-DWITH_TESTS=OFF"
              "-DWITH_HIVE=OFF"
              "-DUSE_JEMALLOC=OFF"
              "-DNATIVE_BUILD=OFF"
              "-DWITH_SYSTEMD=OFF"
              "-DSUBMODULE_CHECK=OFF"
              "-DBUILD_SHARED_LIBS=ON"
              "-DOXEN_LOGGING_FMT_HEADER_ONLY=ON"
              "-DOXEN_LOGGING_SPDLOG_HEADER_ONLY=ON"
              "-DCMAKE_INSTALL_LIBDIR=lib"
            ];
          };
          staticSources = {
            openssl = pkgs.fetchurl {
              url = "https://www.openssl.org/source/openssl-3.0.7.tar.gz";
              hash = "sha256-gwSdBComDmlvYkBqxcCL9wb9hDg/lFzyG9YentlcOW4=";
            };
            expat = pkgs.fetchurl {
              url = "https://github.com/libexpat/libexpat/releases/download/R_2_5_0/expat-2.5.0.tar.xz";
              hash = "sha256-7yQg8CMsCHgBq/cF6JrmX2JX32t5MdN4RqGT7y6M3L4=";
            };
            unbound = pkgs.fetchurl {
              url = "https://nlnetlabs.nl/downloads/unbound/unbound-1.17.0.tar.gz";
              hash = "sha256-3LyV14kdn5EMZuTtyfHy/eTeou7Bjjr591rtRKAvE0E=";
            };
            sqlite = pkgs.fetchurl {
              url = "https://www.sqlite.org/2022/sqlite-autoconf-3400000.tar.gz";
              hash = "sha256-AzNVIHbScAx1NSJW6Rx4v1zWJJFYm6DGmu0KgYaJgOc=";
            };
            sodium = pkgs.fetchurl {
              url = "https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz";
              hash = "sha256-b1BEkLNCpPikxKAvybhmy++GItXfTlRStGvhIeRmNsE=";
            };
            zmq = pkgs.fetchurl {
              url = "https://github.com/zeromq/libzmq/releases/download/v4.3.4/zeromq-4.3.4.tar.gz";
              hash = "sha256-xZMAGon1qF3S3fVkgF3rhg4CRxFxs/IElEhXM2KVw+U=";
            };
            libuv = pkgs.fetchurl {
              url = "https://dist.libuv.org/dist/v1.44.2/libuv-v1.44.2.tar.gz";
              hash = "sha512-kRl/+TAxElZ7u5Fbu4gFgFDirRwEiBWjtXwFRjXV3H30WLlWCJ14VHUpATIjbLDtz66DD110neKamjIT7q8LIA==";
            };
            zlib = pkgs.fetchurl {
              url = "https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.xz";
              hash = "sha256-0Uw44xOvw1qah2Da3yYEL1HqD10VSwYwox2gVAEH+5g=";
            };
            curl = pkgs.fetchurl {
              url = "https://curl.haxx.se/download/curl-7.86.0.tar.xz";
              hash = "sha256-LWERbl9IVYH21ZhlN330Rj8ueIZ3rEMiK0ltTkn7Yns=";
            };
          };
          staticSourceMirror = pkgs.linkFarm "lokinet-static-source-mirror" [
            { name = "openssl-3.0.7.tar.gz"; path = staticSources.openssl; }
            { name = "expat-2.5.0.tar.xz"; path = staticSources.expat; }
            { name = "unbound-1.17.0.tar.gz"; path = staticSources.unbound; }
            { name = "sqlite-autoconf-3400000.tar.gz"; path = staticSources.sqlite; }
            { name = "libsodium-1.0.18.tar.gz"; path = staticSources.sodium; }
            { name = "zeromq-4.3.4.tar.gz"; path = staticSources.zmq; }
            { name = "libuv-v1.44.2.tar.gz"; path = staticSources.libuv; }
            { name = "zlib-1.2.13.tar.xz"; path = staticSources.zlib; }
            { name = "curl-7.86.0.tar.xz"; path = staticSources.curl; }
          ];
          lokinetEmbeddedStatic = lokinetEmbedded.overrideAttrs (old: {
            pname = "lokinet-embedded-static";
            cmakeFlags =
              builtins.filter (flag: flag != "-DBUILD_SHARED_LIBS=ON") old.cmakeFlags
              ++ [
                "-DBUILD_STATIC_DEPS=ON"
                "-DSTATIC_LINK=ON"
                "-DBUILD_SHARED_LIBS=OFF"
                "-DLOCAL_MIRROR=file://${staticSourceMirror}"
              ];
          });
          rsLokinet = pkgs.rustPlatform.buildRustPackage {
            pname = "rs-lokinet";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "-p" "rs-lokinet" ];
            cargoTestFlags = [ "-p" "rs-lokinet" ];
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ lokinetEmbedded ];
            PKG_CONFIG_PATH = "${lokinetEmbedded}/lib/pkgconfig";
          };
        in
        {
          lokinet-embedded = lokinetEmbedded;
          lokinet-embedded-static = lokinetEmbeddedStatic;
          rs-lokinet = rsLokinet;
          default = rsLokinet;
        });
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
              pkgs.rustc
              pkgs.cargo
              pkgs.rustfmt
            ];
            inputsFrom = [ packages.${system}.lokinet-embedded ];
            PKG_CONFIG_PATH = "${packages.${system}.lokinet-embedded}/lib/pkgconfig";
            LD_LIBRARY_PATH = "${packages.${system}.lokinet-embedded}/lib";
          };
        });
    in
    {
      inherit packages devShells;
    };
}
