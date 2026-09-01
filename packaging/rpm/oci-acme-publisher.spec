Name:           oci-acme-publisher
Version:        %{!?version:2.0.0}%{?version}
Release:        6%{?dist}
Summary:        ACME HTTP-01 certificate publisher for OCI Certificates
License:         Apache-2.0
ExclusiveArch:   x86_64
Source0:         %{name}-%{version}.tar.gz
Source1:         %{name}-%{version}-wheelhouse.tar.gz
Requires:        python3 >= 3.12
Requires(posttrans): systemd

%description
OCI ACME Publisher is a systemd-managed service that obtains ACME
HTTP-01 certificates and publishes validated versions to OCI Certificates.
The RPM ships all Python dependency wheels required to create its isolated
runtime without accessing a package index during installation or upgrade.
The RPM includes the native Python ACME protocol client and all of its locked
dependencies. No external certificate client or subprocess is required.
Use the supplied upgrade command rather than invoking `dnf` directly so an
active responder and timer are stopped and restored around the runtime swap.

%prep
%setup -q -n %{name}-%{version}

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_datadir}/oci-acme-publisher/wheelhouse
install -m 0644 requirements.lock %{buildroot}%{_datadir}/oci-acme-publisher/requirements.lock
tar -xzf %{SOURCE1} -C %{buildroot}%{_datadir}/oci-acme-publisher/wheelhouse
install -D -m 0755 packaging/rpm/bootstrap-runtime \
  %{buildroot}%{_libexecdir}/oci-acme-publisher/bootstrap-runtime
install -D -m 0755 scripts/verify-rpm.sh \
  %{buildroot}%{_libexecdir}/oci-acme-publisher/verify-rpm.sh
install -D -m 0755 scripts/upgrade-oracle-linux.sh \
  %{buildroot}%{_libexecdir}/oci-acme-publisher/upgrade-oracle-linux.sh
install -D -m 0644 deploy/systemd/oci-acme-http01.service \
  %{buildroot}%{_unitdir}/oci-acme-http01.service
install -D -m 0644 deploy/systemd/oci-acme-renew.service \
  %{buildroot}%{_unitdir}/oci-acme-renew.service
install -D -m 0644 deploy/systemd/oci-acme-renew.timer \
  %{buildroot}%{_unitdir}/oci-acme-renew.timer
install -D -m 0644 deploy/sysusers.d/oci-acme-publisher.conf \
  %{buildroot}/usr/lib/sysusers.d/oci-acme-publisher.conf
install -D -m 0644 deploy/tmpfiles.d/oci-acme-publisher.conf \
  %{buildroot}/usr/lib/tmpfiles.d/oci-acme-publisher.conf
install -d -m 0755 %{buildroot}%{_bindir}
printf '%s\n' '#!/usr/bin/env bash' \
  'exec /opt/oci-acme-publisher/venv/bin/oci-acme "$@"' > %{buildroot}%{_bindir}/oci-acme
chmod 0755 %{buildroot}%{_bindir}/oci-acme
printf '%s\n' '#!/usr/bin/env bash' \
  'exec /usr/libexec/oci-acme-publisher/upgrade-oracle-linux.sh "$@"' > %{buildroot}%{_bindir}/oci-acme-upgrade
chmod 0755 %{buildroot}%{_bindir}/oci-acme-upgrade

%posttrans
%{_libexecdir}/oci-acme-publisher/bootstrap-runtime
systemd-sysusers /usr/lib/sysusers.d/oci-acme-publisher.conf || :
systemd-tmpfiles --create /usr/lib/tmpfiles.d/oci-acme-publisher.conf || :
systemctl daemon-reload || :

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now oci-acme-renew.timer oci-acme-http01.service || :
fi

%postun
if [ "$1" -eq 0 ]; then
  systemctl daemon-reload || :
fi

%files
%license LICENSE
%doc README.md docs/*.md
%{_bindir}/oci-acme
%{_bindir}/oci-acme-upgrade
%{_libexecdir}/oci-acme-publisher/bootstrap-runtime
%{_libexecdir}/oci-acme-publisher/verify-rpm.sh
%{_libexecdir}/oci-acme-publisher/upgrade-oracle-linux.sh
%{_datadir}/oci-acme-publisher
%{_unitdir}/oci-acme-http01.service
%{_unitdir}/oci-acme-renew.service
%{_unitdir}/oci-acme-renew.timer
/usr/lib/sysusers.d/oci-acme-publisher.conf
/usr/lib/tmpfiles.d/oci-acme-publisher.conf

%changelog
* Mon Aug 31 2026 OCI ACME Publisher contributors - 2.0.0-6
- Reuse an existing native ACME account across certificate sets.
- Reconcile OCI lifecycle and throttling windows before promotion.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 2.0.0-5
- Report the installed 2.0.0 application version consistently.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 2.0.0-4
- Qualify CA-independent request shapes with schema-v2 Gate 0 evidence.
- Keep production issuer allowlists and root pins independently enforced.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 2.0.0-3
- Use the native Python ACME protocol implementation and generation store.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 1.0.0-3
- Accept legacy live attestations at load time while mutation remains evidence-gated.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 1.0.0-2
- Preserve console-script interpreter paths during atomic runtime swaps.

* Mon Aug 31 2026 OCI ACME Publisher contributors - 1.0.0-1
- Initial RPM release.
