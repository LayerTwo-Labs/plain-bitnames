{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    autoconf
    automake
    boost
    db4
    gcc
    libevent
    libtool
    openssl
    pkg-config
  ];
  # Needed for X11
  shellHook =
    let x11-libs = with pkgs; lib.makeLibraryPath [
        libGL
        xorg.libX11
        xorg.libXcursor
        xorg.libXi
        xorg.libXrandr
    ]; in ''
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${x11-libs}"
      export BOOST_LIB_DIR="${pkgs.boost.out}/lib"
    '';
}
