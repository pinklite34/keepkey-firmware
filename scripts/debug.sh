#! /bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")"

openocd -s /usr/share/openocd/scripts \
    -f "$KEEPKEY_FIRMWARE/scripts/openocd/openocd.cfg" \
    "$KEEPKEY_FIRMWARE/scripts/openocd/stm32f2x.cfg" \
    -c "init" -c "halt" -c "reset halt"
-----BEGIN CERTIFICATE-----

MIIB8TCCAVoCCQCg2ZYlANUEvjANBgkqhkiG9w0BAQsFADA9MQswCQYDVQQGEwJV

UzELMAkGA1UECAwCQ0ExITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0

ZDAeFw0xNDA4MTgyMzE5NDJaFw0xNTA4MTgyMzE5NDJaMD0xCzAJBgNVBAYTAlVT

MQswCQYDVQQIDAJDQTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk

MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDV4suKtPRyipQJg35O/wIndwm+

5RV+s+jqo8VS7tJ1E4OIsSMo7eVuNU4pLTIqehNN+Skyk/i17y6cPwo2Mff+E6VB

lJrjNLO+rI+B7Ttx7Cs9imoE38Pmv0LKzQbAz8Uz3T6zxXHJpjIWA4PKiw+mO6qw

niEDDutypPa2mB+KjQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAHUfkcY4wNZZGT3f

oCoB0cNy+gtS86Iu2XU+WzKWxQxvgSiloQ2l0NDsRlw9wBQQZNQOJtPNfTIXkpfU

NoD7qU0Dd0TawoIRAetWzweW0PIJt+Dh7/z7FUTXg5p2IRhOPVNA9+K1wBGfOkEF

6cYkdpr0FmQ52L+Vc1QcNCxwYtWm

-----END CERTIFICATE-----

resource "google_compute_network" "mesos-global-net" {

    name                    = "${var.name}-global-net"

    auto_create_subnetworks = false # custom subnetted network will be created that can support google_compute_subnetwork resources

}



resource "google_compute_subnetwork" "mesos-net" {

    name          = "${var.name}-${var.region}-net"

    ip_cidr_range = "${var.subnetwork}"

    network       = "${google_compute_network.mesos-global-net.self_link}" # parent network

}
