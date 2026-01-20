package app.k9mail.autodiscovery.autoconfig

import app.k9mail.autodiscovery.api.AutoDiscovery
import app.k9mail.autodiscovery.api.AutoDiscoveryResult
import app.k9mail.autodiscovery.api.AutoDiscoveryRunnable
import app.k9mail.autodiscovery.api.ImapServerSettings
import app.k9mail.autodiscovery.api.SmtpServerSettings
import app.k9mail.autodiscovery.api.ConnectionSecurity
import app.k9mail.autodiscovery.api.AuthenticationType
import net.thunderbird.core.common.mail.EmailAddress
import net.thunderbird.core.common.net.Hostname
import net.thunderbird.core.common.net.Port

class FaberSoftAutoconfigDiscovery : AutoDiscovery {

    private val parser = RealAutoconfigParser()

    override fun initDiscovery(email: EmailAddress): List<AutoDiscoveryRunnable> {
        return listOf(AutoDiscoveryRunnable {
            val domain = email.domain.value.trim().lowercase()

            val customDomains = listOf(
                "arubapec.it", "legalmail.it", "postecert.it", "sicurezzapostale.it"
            )

            // 1. GESTIONE PEC (Tramite XML)
            if (domain in customDomains) {
                val resourcePath = "/protocols/$domain.xml"
                val inputStream = javaClass.getResourceAsStream(resourcePath)

                if (inputStream != null) {
                    val parserResult = parser.parseSettings(inputStream, email)
                    if (parserResult is AutoconfigParserResult.Settings) {
                        return@AutoDiscoveryRunnable AutoDiscoveryResult.Settings(
                            incomingServerSettings = parserResult.incomingServerSettings.first(),
                            outgoingServerSettings = parserResult.outgoingServerSettings.first(),
                            isTrusted = true,
                            source = "PEC $domain"
                        )
                    }
                }
            }

            // 2. GESTIONE MASTER FABERSOFT (Manuale - Come nel vecchio progetto che funzionava)
            // Usiamo questa logica per QUALSIASI altro dominio, forzando i tuoi server
            return@AutoDiscoveryRunnable AutoDiscoveryResult.Settings(
                incomingServerSettings = ImapServerSettings(
                    hostname = Hostname("imap.mobile-mail.it"),
                    port = Port(993),
                    connectionSecurity = ConnectionSecurity.TLS,
                    authenticationTypes = listOf(AuthenticationType.PasswordCleartext),
                    username = email.address // Email reale dell'utente
                ),
                outgoingServerSettings = SmtpServerSettings(
                    hostname = Hostname("smtp.mobile-mail.it"),
                    port = Port(465),
                    connectionSecurity = ConnectionSecurity.TLS,
                    authenticationTypes = listOf(AuthenticationType.PasswordCleartext),
                    username = email.address // Email reale dell'utente
                ),
                isTrusted = true,
                source = "Bibi Mail Master"
            )
        })
    }
}
