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
