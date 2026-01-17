Name:           secexit
Version:        0.1.0
Release:        1%{?dist}
Summary:        Egress control daemon using eBPF

License:        MIT
URL:            https://github.com/secexit/secexit
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  kernel-headers
BuildRequires:  systemd-rpm-macros

Requires:       systemd

%description
secexit blocks unauthorized outbound traffic using eBPF. This package ships the
daemon and the LD_PRELOAD shim library.

%prep
%autosetup -n %{name}-%{version}

%build
export RUSTUP_TOOLCHAIN=nightly
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
cargo install cargo-xtask
cargo run -p xtask -- build-ebpf --release
cargo build --release -p secexit-daemon -p secexit-shim

%install
install -Dpm0755 target/release/secexit-daemon %{buildroot}%{_bindir}/secexit-daemon
install -Dpm0755 target/release/libsecexit_shim.so %{buildroot}%{_libdir}/libsecexit_shim.so
install -Dpm0644 packaging/secexit-daemon.service %{buildroot}%{_unitdir}/secexit-daemon.service
install -Dpm0644 example-policy.json %{buildroot}%{_sysconfdir}/secexit/policy.json

%post
%systemd_post secexit-daemon.service

%preun
%systemd_preun secexit-daemon.service

%postun
%systemd_postun_with_restart secexit-daemon.service

%files
%license LICENSE
%doc README.md
%config(noreplace) %{_sysconfdir}/secexit/policy.json
%{_bindir}/secexit-daemon
%{_libdir}/libsecexit_shim.so
%{_unitdir}/secexit-daemon.service
