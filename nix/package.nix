# ReFineID package: the refineid CLI, the Card Manager GUI, and the
# PKCS#11 module, built from this source tree with the Rust that
# nixpkgs ships.
{
  lib,
  rustPlatform,
  pkg-config,
  pcsclite,
  fontconfig,
  # Runtime graphics/windowing stack for the Slint (winit + femtovg)
  # GUI. These are dlopened, not linked, so they go on the rpath.
  libGL,
  libxkbcommon,
  wayland,
  libx11,
  libxcursor,
  libxi,
  libxrandr,
}:

rustPlatform.buildRustPackage {
  pname = "refineid";
  version = lib.trim (builtins.readFile ../VERSION);

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      base != "target" && base != "result" && base != ".git" && base != "nix";
  };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    pcsclite
    fontconfig
  ];

  # The GUI dlopens its windowing/GL stack at runtime.
  runtimeLibs = lib.makeLibraryPath [
    libGL
    libxkbcommon
    wayland
    libx11
    libxcursor
    libxi
    libxrandr
  ];

  postFixup = ''
    patchelf --add-rpath "$runtimeLibs" $out/bin/refineid-card-manager
  '';

  postInstall = ''
    # The PKCS#11 cdylib (cargoInstallHook already places it in
    # $out/lib; assert so a hook change cannot ship a package
    # silently missing the module).
    test -f $out/lib/librefineid_pkcs11.so

    # p11-kit module config: every p11-kit-aware consumer (Firefox
    # via p11-kit-proxy, OpenSSL via pkcs11-provider, GnuTLS,
    # OpenSSH) loads the module with no per-user configuration.
    mkdir -p $out/share/p11-kit/modules
    cat > $out/share/p11-kit/modules/refineid.module <<EOF
    module: $out/lib/librefineid_pkcs11.so
    # Citizen client-auth keys, not CA trust anchors.
    trust-policy: no
    # A load failure must not take down every crypto consumer.
    critical: no
    EOF

    # Desktop entry + icon for the Card Manager.
    mkdir -p $out/share/applications $out/share/icons/hicolor/scalable/apps
    cp crates/refineid-card-manager/assets/app-icon.svg \
      $out/share/icons/hicolor/scalable/apps/refineid-card-manager.svg
    cat > $out/share/applications/refineid-card-manager.desktop <<EOF
    [Desktop Entry]
    Type=Application
    Name=ReFineID Card Manager
    Comment=Manage Finnish identity card PINs, portrait and signature
    Exec=$out/bin/refineid-card-manager
    Icon=refineid-card-manager
    Categories=Utility;Security;
    EOF
  '';

  meta = {
    description = "Open-source FINEID middleware: CLI, PKCS#11 module, and card-manager GUI";
    homepage = "https://github.com/ReFineID/ReFineID-Unix";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "refineid";
  };
}
