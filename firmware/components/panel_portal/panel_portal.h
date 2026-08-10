#pragma once

#include "esphome/core/component.h"
#include "esphome/components/web_server_base/web_server_base.h"

namespace esphome::panel_portal {

class PanelPortal : public AsyncWebHandler, public Component {
 public:
  explicit PanelPortal(web_server_base::WebServerBase *base) : base_(base) {}

  void setup() override;
  float get_setup_priority() const override;
  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;

 protected:
  web_server_base::WebServerBase *base_;
};

}  // namespace esphome::panel_portal
