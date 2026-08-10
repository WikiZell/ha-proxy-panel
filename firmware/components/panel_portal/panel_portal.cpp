#include "panel_portal.h"

#include "esphome/components/captive_portal/captive_portal.h"
#include "esphome/core/helpers.h"
#include "portal_index.h"

namespace esphome::panel_portal {

void PanelPortal::setup() { this->base_->add_handler_without_auth(this); }

float PanelPortal::get_setup_priority() const {
  return setup_priority::WIFI + 2.0f;
}

bool PanelPortal::canHandle(AsyncWebServerRequest *request) const {
  if (captive_portal::global_captive_portal == nullptr ||
      !captive_portal::global_captive_portal->is_active() ||
      request->method() != HTTP_GET) {
    return false;
  }
#ifdef USE_ESP32
  char url_buf[AsyncWebServerRequest::URL_BUF_SIZE];
  StringRef url = request->url_to(url_buf);
#else
  const auto &url = request->url();
#endif
  return url != ESPHOME_F("/config.json") && url != ESPHOME_F("/wifisave");
}

void PanelPortal::handleRequest(AsyncWebServerRequest *request) {
#ifndef USE_ESP8266
  auto *response = request->beginResponse(200, ESPHOME_F("text/html"), PORTAL_INDEX_GZ,
                                          sizeof(PORTAL_INDEX_GZ));
#else
  auto *response = request->beginResponse_P(200, ESPHOME_F("text/html"), PORTAL_INDEX_GZ,
                                            sizeof(PORTAL_INDEX_GZ));
#endif
  response->addHeader(ESPHOME_F("Content-Encoding"), ESPHOME_F("gzip"));
  response->addHeader(ESPHOME_F("Cache-Control"), ESPHOME_F("no-store"));
  request->send(response);
}

}  // namespace esphome::panel_portal
