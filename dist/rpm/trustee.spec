%define alinux_release 1
%global _prefix /usr/local
%global config_dir /etc/trustee

Name:           trustee
Version:        1.0.1
Release:	    %{alinux_release}%{?dist}
Summary:        Daemon services for attestation and secret distribution
Group:          Applications/System
BuildArch:      x86_64

License:        Apache-2.0

Requires: openssl

%description
Trustee are daemon services for attestation and secret distribution.

%prep
find . -mindepth 1 -delete
mkdir -p ./trustee
cp -af `find %{expand:%%(pwd)}/ -maxdepth 1 -mindepth 1 | grep -vE target` ./trustee

%build
mkdir -p ./trustee
pushd trustee/kbs
make AS_FEATURE=coco-as-grpc HTTPS_CRYPTO=rustls POLICY_ENGINE=opa ALIYUN=true
make cli
popd
pushd trustee/attestation-service
cargo build --bin restful-as --release --features restful-bin --locked
cargo build --bin grpc-as --release --features grpc-bin --locked
popd
pushd trustee/rvps
cargo build --bin rvps --release
cargo build --bin rvps-tool --release
popd

%install
pushd trustee
install -d -p %{buildroot}%{_prefix}/lib/systemd/system
install -m 644 dist/rpm/systemd/kbs.service %{buildroot}%{_prefix}/lib/systemd/system/kbs.service
install -m 644 dist/rpm/systemd/as.service %{buildroot}%{_prefix}/lib/systemd/system/as.service
install -m 644 dist/rpm/systemd/rvps.service %{buildroot}%{_prefix}/lib/systemd/system/rvps.service
install -m 644 dist/rpm/systemd/as-restful.service %{buildroot}%{_prefix}/lib/systemd/system/as-restful.service
install -m 644 dist/rpm/systemd/trustee.service %{buildroot}%{_prefix}/lib/systemd/system/trustee.service
install -d -p %{buildroot}/etc/trustee
install -m 644 dist/rpm/configs/kbs-config.toml %{buildroot}%{config_dir}/kbs-config.toml
install -m 644 dist/rpm/configs/as-config.json %{buildroot}%{config_dir}/as-config.json
install -m 644 dist/rpm/configs/rvps.json %{buildroot}%{config_dir}/rvps.json
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/release/kbs %{buildroot}%{_prefix}/bin/kbs
install -m 755 target/release/restful-as %{buildroot}%{_prefix}/bin/restful-as
install -m 755 target/release/grpc-as %{buildroot}%{_prefix}/bin/grpc-as
install -m 755 target/release/rvps %{buildroot}%{_prefix}/bin/rvps
install -m 755 target/release/kbs-client %{buildroot}%{_prefix}/bin/kbs-client
install -m 755 target/release/rvps-tool %{buildroot}%{_prefix}/bin/rvps-tool

%post
systemctl daemon-reload
openssl genpkey -algorithm ed25519 > /etc/trustee/private.key
openssl pkey -in /etc/trustee/private.key -pubout -out /etc/trustee/public.pub
systemctl start trustee

%preun
if [ $1 == 0 ]; then #uninstall
  systemctl unmask trustee kbs as as-restful rvps
  systemctl stop trustee kbs as as-restful rvps
  systemctl disable trustee kbs as as-restful rvps
  rm -rf /etc/trustee/private.key /etc/trustee/public.pub
fi

%postun
if [ $1 == 0 ]; then #uninstall
  systemctl daemon-reload
  systemctl reset-failed
fi

%files
%{_prefix}/bin/kbs
%{_prefix}/bin/grpc-as
%{_prefix}/bin/restful-as
%{_prefix}/bin/rvps
%{_prefix}/bin/kbs-client
%{_prefix}/bin/rvps-tool
%{config_dir}/kbs-config.toml
%{config_dir}/as-config.json
%{config_dir}/rvps.json
%{_prefix}/lib/systemd/system/kbs.service
%{_prefix}/lib/systemd/system/as.service
%{_prefix}/lib/systemd/system/as-restful.service
%{_prefix}/lib/systemd/system/rvps.service
%{_prefix}/lib/systemd/system/trustee.service

%changelog
* Thu Apr 2 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.0.1-1
- First release