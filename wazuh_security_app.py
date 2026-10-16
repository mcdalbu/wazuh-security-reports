#!/usr/bin/env python3
"""GTK4/libadwaita interface for customer Wazuh security reports."""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from pathlib import Path

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, Gtk
except (ImportError, ValueError) as error:
    raise SystemExit(
        "GTK4/libadwaita não estão disponíveis. Consulte README.md para instalar as dependências."
    ) from error

from wazuh_report import (DEFAULT_OUTPUT_DIR, PERIODS, default_filename, fetch_summary,
                          indexer_url, render_report, validate_customer)


class ReportWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application):
        super().__init__(application=application, title="Relatórios de Segurança Wazuh")
        self.set_default_size(760, 680)
        self.last_pdf: Path | None = None
        self.busy = False

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle(title="Relatórios de Segurança", subtitle="Wazuh Indexer"))
        toolbar.add_top_bar(header)
        self.toasts = Adw.ToastOverlay()
        self.toasts.set_child(toolbar)
        self.set_content(self.toasts)

        page = Adw.PreferencesPage()
        toolbar.set_content(page)

        scope = Adw.PreferencesGroup(
            title="Relatório",
            description="Informe o valor exato de agent.labels.customer e escolha o período.",
        )
        page.add(scope)
        self.customer = Adw.EntryRow(title="agent.labels.customer")
        self.customer.connect("changed", self._validate)
        scope.add(self.customer)
        self.period_hours = tuple(PERIODS)
        self.time_range = Adw.ComboRow(
            title="Período",
            model=Gtk.StringList.new([PERIODS[hours][0] for hours in self.period_hours]),
        )
        self.time_range.set_selected(0)
        scope.add(self.time_range)

        connection = Adw.PreferencesGroup(
            title="Indexador Wazuh",
            description="A senha é usada apenas na consulta e não é salva no disco.",
        )
        page.add(connection)
        self.server_ip = Adw.EntryRow(title="IP do Wazuh Indexer")
        self.server_ip.set_text(os.environ.get("WAZUH_INDEXER_IP", ""))
        connection.add(self.server_ip)
        self.server_port = Adw.EntryRow(title="Porta do Wazuh Indexer")
        self.server_port.set_text(os.environ.get("WAZUH_INDEXER_PORT", "9200"))
        connection.add(self.server_port)
        self.username = Adw.EntryRow(title="Usuário")
        self.username.set_text(os.environ.get("WAZUH_INDEXER_USER", ""))
        connection.add(self.username)
        self.password = Adw.PasswordEntryRow(title="Senha")
        self.password.set_text(os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
        connection.add(self.password)
        self.verify_tls = Adw.SwitchRow(
            title="Validar certificado TLS",
            subtitle="Ative quando o certificado do indexador for confiável neste computador.",
        )
        self.verify_tls.set_active(False)
        connection.add(self.verify_tls)

        output = Adw.PreferencesGroup(title="Arquivo de saída")
        page.add(output)
        self.output_folder = Adw.EntryRow(title="Pasta para salvar o PDF")
        self.output_folder.set_text(str(DEFAULT_OUTPUT_DIR))
        folder_button = Gtk.Button(icon_name="folder-open-symbolic", valign=Gtk.Align.CENTER)
        folder_button.set_tooltip_text("Escolher pasta")
        folder_button.add_css_class("flat")
        folder_button.connect("clicked", self._choose_folder)
        self.output_folder.add_suffix(folder_button)
        output.add(self.output_folder)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions.set_margin_top(18)
        actions.set_margin_bottom(10)
        self.generate_button = Gtk.Button(label="Gerar relatório")
        self.generate_button.add_css_class("suggested-action")
        self.generate_button.connect("clicked", self._start)
        actions.append(self.generate_button)
        self.spinner = Gtk.Spinner()
        actions.append(self.spinner)
        self.open_button = Gtk.Button(label="Abrir PDF")
        self.open_button.set_sensitive(False)
        self.open_button.connect("clicked", self._open_pdf)
        actions.append(self.open_button)
        action_group = Adw.PreferencesGroup()
        action_group.add(actions)
        page.add(action_group)

        self.status = Gtk.Label(label="Pronto para gerar o relatório.", xalign=0)
        self.status.set_wrap(True)
        self.status.add_css_class("dim-label")
        status_group = Adw.PreferencesGroup()
        status_group.add(self.status)
        page.add(status_group)
        self._validate()

    def _validate(self, *_args):
        self.generate_button.set_sensitive(not self.busy and bool(self.customer.get_text().strip()))

    def _choose_folder(self, *_args):
        dialog = Gtk.FileDialog(title="Escolher pasta para o relatório")
        dialog.select_folder(self, None, self._folder_selected)

    def _folder_selected(self, dialog: Gtk.FileDialog, result):
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return
        path = folder.get_path()
        if path:
            self.output_folder.set_text(path)

    def _start(self, *_args):
        try:
            customer = validate_customer(self.customer.get_text())
            hours = self.period_hours[self.time_range.get_selected()]
            server = indexer_url(self.server_ip.get_text(), self.server_port.get_text())
            folder_text = self.output_folder.get_text().strip()
            if not folder_text:
                raise ValueError("Informe a pasta de saída.")
            folder = Path(folder_text).expanduser()
            args = (customer, hours, server, self.username.get_text(),
                    self.password.get_text(), self.verify_tls.get_active(), folder)
        except ValueError as error:
            self._show_error(str(error))
            return
        self.busy = True
        self._validate()
        self.open_button.set_sensitive(False)
        self.spinner.start()
        self.status.set_text(f"Consultando os alertas dos últimos {PERIODS[hours][0]}…")
        threading.Thread(target=self._work, args=args, daemon=True).start()

    def _work(self, customer: str, hours: int, server: str, username: str, password: str,
              verify_tls: bool, folder: Path):
        try:
            snapshot = fetch_summary(customer, server, username, password,
                                     hours=hours, verify_tls=verify_tls)
            GLib.idle_add(self.status.set_text, "Gerando o PDF com gráficos e papel timbrado…")
            destination = folder / default_filename(customer, now=datetime.fromisoformat(snapshot["end_utc"]))
            render_report(snapshot, destination)
        except Exception as error:
            GLib.idle_add(self._finished_error, str(error))
        else:
            total = snapshot["result"]["hits"]["total"]["value"]
            GLib.idle_add(self._finished_success, destination, total)

    def _finished_error(self, message: str):
        self.spinner.stop()
        self.busy = False
        self._validate()
        self._show_error(message)
        return False

    def _finished_success(self, path: Path, total: int):
        self.spinner.stop()
        self.busy = False
        self._validate()
        self.open_button.set_sensitive(True)
        self.last_pdf = path
        count = f"{total:,}".replace(",", ".")
        self.status.set_text(f"Relatório salvo em {path} — {count} alertas.")
        self.toasts.add_toast(Adw.Toast(title="Relatório gerado com sucesso"))
        return False

    def _show_error(self, message: str):
        self.status.set_text(message)
        self.toasts.add_toast(Adw.Toast(title="Não foi possível gerar o relatório"))

    def _open_pdf(self, *_args):
        if not self.last_pdf:
            return
        try:
            Gio.AppInfo.launch_default_for_uri(self.last_pdf.as_uri(), None)
        except GLib.Error as error:
            self._show_error(f"Não foi possível abrir o PDF: {error.message}")


class ReportApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id="br.com.hostdime.WazuhSecurityReports")
        self.window: ReportWindow | None = None

    def do_activate(self):
        if self.window is None:
            self.window = ReportWindow(self)
        self.window.present()


if __name__ == "__main__":
    raise SystemExit(ReportApplication().run(sys.argv))
