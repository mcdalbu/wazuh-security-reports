Name:           wazuh-security-reports
Version:        0.3.1
Release:        1%{?dist}
Summary:        GTK4 application for customer Wazuh security reports
License:        LicenseRef-Internal
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 >= 3.10
Requires:       python3-gobject
Requires:       gtk4 >= 4.10
Requires:       libadwaita >= 1.4
Requires:       python3-reportlab
Requires:       python3-pypdf
Requires:       dejavu-sans-fonts

%description
Generates customer-scoped Wazuh security reports as branded PDFs with charts.
The application asks for an exact agent.labels.customer value and queries the
last 24 hours, 7 days or 30 days from the alert indexer.

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}%{_datadir}/wazuh-security-reports/assets
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/512x512/apps
mkdir -p %{buildroot}%{_docdir}/%{name}
install -m 0644 wazuh_report.py wazuh_security_app.py %{buildroot}%{_datadir}/wazuh-security-reports/
install -m 0644 assets/timbrado_confidencial.pdf %{buildroot}%{_datadir}/wazuh-security-reports/assets/
install -m 0755 packaging/wazuh-security-reports %{buildroot}%{_bindir}/
install -m 0644 packaging/br.com.hostdime.WazuhSecurityReports.desktop %{buildroot}%{_datadir}/applications/
install -m 0644 assets/br.com.hostdime.WazuhSecurityReports.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/
install -m 0644 assets/br.com.hostdime.WazuhSecurityReports.png %{buildroot}%{_datadir}/icons/hicolor/512x512/apps/
install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/
install -m 0644 modelo_relatorio_seguranca.md %{buildroot}%{_docdir}/%{name}/

%files
%{_bindir}/wazuh-security-reports
%{_datadir}/applications/br.com.hostdime.WazuhSecurityReports.desktop
%{_datadir}/icons/hicolor/scalable/apps/br.com.hostdime.WazuhSecurityReports.svg
%{_datadir}/icons/hicolor/512x512/apps/br.com.hostdime.WazuhSecurityReports.png
%{_datadir}/wazuh-security-reports/wazuh_report.py
%{_datadir}/wazuh-security-reports/wazuh_security_app.py
%{_datadir}/wazuh-security-reports/assets/timbrado_confidencial.pdf
%{_docdir}/%{name}/README.md
%{_docdir}/%{name}/modelo_relatorio_seguranca.md

