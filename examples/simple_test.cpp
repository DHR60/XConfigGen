#include "XConfigGen.h"

XConfigGen::Xray::XrayConfig generateConfig()
{
    XConfigGen::Xray::XrayConfig xrayConfig;
    xrayConfig.log.loglevel = "warning";
    xrayConfig.dns.hosts = {
        {"dns.alidns.com",                   QStringList {"223.5.5.5", "223.6.6.6"}          },
        {"cloudflare-dns.com",               QStringList {"1.1.1.1", "1.0.0.1"}              },
        {"1dot1dot1dot1.cloudflare-dns.com", QStringList {"1.1.1.1", "1.0.0.1"}              },
        {"one.one.one.one",                  QStringList {"1.1.1.1", "1.0.0.1"}              },
        {"dns.google",                       QStringList {"8.8.8.8", "8.8.4.4"}              },
        {"dns.quad9.net",                    QStringList {"9.9.9.9", "149.112.112.112"}      },
        {"dot.pub",                          QStringList {"1.12.12.12", "120.53.53.53"}      },
        {"dns.sb",                           "185.222.222.222"                               },
        {"dns.umbrella.com",                 QStringList {"208.67.220.220", "208.67.222.222"}},
        {"dns.sse.cisco.com",                QStringList {"208.67.220.220", "208.67.222.222"}}
    };
    XConfigGen::Xray::DnsServers4Ray cfDns;
    cfDns.address = "https://1.1.1.1/dns-query";
    cfDns.domains = {
        "domain:bing.com",
        "geosite:geolocation-!cn"};
    cfDns.expectIPs = {
        "geoip:!cn"};
    XConfigGen::Xray::DnsServers4Ray localhostDns;
    localhostDns.address = "localhost";
    localhostDns.domains = {
        "domain:online-fix.me",
        "geosite:cn",
        "geosite:category-games@cn"};
    localhostDns.expectIPs = {
        "geoip:cn"};
    localhostDns.skipFallback = true;
    xrayConfig.dns.servers = {
        QVariant::fromValue(cfDns),
        QVariant::fromValue(localhostDns),
        "https://dns.google/dns-query",
        "https://dns.sb/dns-query",
        "https://dns.sse.cisco.com/dns-query"};

    XConfigGen::Xray::Inbounds4Ray socks1Inbound;
    socks1Inbound.tag = "socks";
    socks1Inbound.protocol = "socks";
    socks1Inbound.listen = "127.0.0.1";
    socks1Inbound.port = 1080;
    socks1Inbound.sniffing.enabled = true;
    socks1Inbound.sniffing.destOverride = {"http", "tls"};
    socks1Inbound.sniffing.routeOnly = false;
    socks1Inbound.settings.auth = "noauth";
    socks1Inbound.settings.udp = true;
    socks1Inbound.settings.allowTransparent = false;

    XConfigGen::Xray::Inbounds4Ray socks3Inbound;
    socks3Inbound.tag = "socks3";
    socks3Inbound.protocol = "socks";
    socks3Inbound.listen = "0.0.0.0";
    socks3Inbound.port = 1082;
    socks3Inbound.sniffing.enabled = true;
    socks3Inbound.sniffing.destOverride = {"http", "tls"};
    socks3Inbound.sniffing.routeOnly = false;
    socks3Inbound.settings.auth = "noauth";
    socks3Inbound.settings.udp = true;
    socks3Inbound.settings.allowTransparent = false;

    XConfigGen::Xray::Inbounds4Ray apiInbound;
    apiInbound.tag = "api";
    apiInbound.port = 1084;
    apiInbound.listen = "127.0.0.1";
    apiInbound.protocol = "dokodemo-door";
    apiInbound.settings.address = "127.0.0.1";

    xrayConfig.inbounds = {socks1Inbound, socks3Inbound, apiInbound};

    XConfigGen::Xray::Outbounds4Ray proxyOutbound;
    proxyOutbound.tag = "proxy";
    proxyOutbound.protocol = "vless";

    XConfigGen::Xray::VnextItem4Ray proxyVnext;
    proxyVnext.address = "proxy.com";
    proxyVnext.port = 443;
    XConfigGen::Xray::UsersItem4Ray proxyUser;
    proxyUser.id = "uuid";
    proxyUser.security = "auto";
    proxyUser.encryption = "none";
    proxyUser.flow = "xtls-rprx-vision";
    proxyVnext.users = {proxyUser};

    XConfigGen::Xray::OutboundSettings4Ray proxySettings;
    proxySettings.vnext = {proxyVnext};

    proxyOutbound.settings = proxySettings;

    XConfigGen::Xray::StreamSettings4Ray proxyStreamSettings;
    proxyStreamSettings.network = "raw";
    proxyStreamSettings.security = "reality";
    XConfigGen::Xray::TlsSettings4Ray proxyRealitySettings;
    proxyRealitySettings.serverName = "fbl.cn";
    proxyRealitySettings.fingerprint = "chrome";
    proxyRealitySettings.show = false;
    proxyRealitySettings.publicKey = "password";
    proxyRealitySettings.shortId = "shortpsword";
    proxyRealitySettings.spiderX = "";
    proxyStreamSettings.realitySettings = proxyRealitySettings;

    proxyOutbound.streamSettings = proxyStreamSettings;

    XConfigGen::Xray::Mux4Ray proxyMux;
    proxyMux.enabled = true;
    proxyMux.concurrency = 8;
    proxyMux.xudpConcurrency = 8;

    proxyOutbound.mux = proxyMux;

    XConfigGen::Xray::Outbounds4Ray directOutbound;
    directOutbound.tag = "direct";
    directOutbound.protocol = "freedom";

    XConfigGen::Xray::Outbounds4Ray blockOutbound;
    blockOutbound.tag = "block";
    blockOutbound.protocol = "blackhole";

    xrayConfig.outbounds = {proxyOutbound, directOutbound, blockOutbound};

    xrayConfig.routing.domainStrategy = "IPIfNonMatch";

    XConfigGen::Xray::RulesItem4Ray apiRule;
    apiRule.type = "field";
    apiRule.inboundTag = {"api"};
    apiRule.outboundTag = "api";

    XConfigGen::Xray::RulesItem4Ray proxyDomainRule;
    proxyDomainRule.type = "field";
    proxyDomainRule.domain = {
        "domain:googleapis.cn",
        "domain:gstatic.com",
        "domain:cloudflare-dns.com",
        "domain:1dot1dot1dot1.cloudflare-dns.com",
        "domain:dns.google",
        "domain:dns.quad9.net",
        "domain:dns.sb",
        "domain:dns.umbrella.com",
        "domain:dns.sse.cisco.com",
        "geosite:cn"};
    proxyDomainRule.outboundTag = "proxy";

    XConfigGen::Xray::RulesItem4Ray blockQuicRule;
    blockQuicRule.type = "field";
    blockQuicRule.port = "443";
    blockQuicRule.network = "udp";
    blockQuicRule.outboundTag = "block";

    XConfigGen::Xray::RulesItem4Ray blockAdsRule;
    blockAdsRule.type = "field";
    blockAdsRule.domain = {
        "geosite:category-ads-all"};
    blockAdsRule.outboundTag = "block";

    XConfigGen::Xray::RulesItem4Ray directPrivateIPRule;
    directPrivateIPRule.type = "field";
    directPrivateIPRule.ip = {
        "geoip:private"};
    directPrivateIPRule.outboundTag = "direct";

    XConfigGen::Xray::RulesItem4Ray directLocalDomainRule;
    directLocalDomainRule.type = "field";
    directLocalDomainRule.domain = {
        "geosite:private"};
    directLocalDomainRule.outboundTag = "direct";

    XConfigGen::Xray::RulesItem4Ray directCNDNSRule;
    directCNDNSRule.type = "field";
    directCNDNSRule.ip = {
        "223.5.5.5",
        "223.6.6.6",
        "2400:3200::1",
        "2400:3200:baba::1",
        "119.29.29.29",
        "1.12.12.12",
        "120.53.53.53",
        "2402:4e00::",
        "2402:4e00:1::",
        "180.76.76.76",
        "2400:da00::6666",
        "114.114.114.114",
        "114.114.115.115",
        "114.114.114.119",
        "114.114.115.119",
        "114.114.114.110",
        "114.114.115.110",
        "180.184.1.1",
        "180.184.2.2",
        "101.226.4.6",
        "218.30.118.6",
        "123.125.81.6",
        "140.207.198.6",
        "1.2.4.8",
        "210.2.4.8",
        "52.80.66.66",
        "117.50.22.22",
        "2400:7fc0:849e:200::4",
        "2404:c2c0:85d8:901::4",
        "117.50.10.10",
        "52.80.52.52",
        "2400:7fc0:849e:200::8",
        "2404:c2c0:85d8:901::8",
        "117.50.60.30",
        "52.80.60.30"};
    directCNDNSRule.outboundTag = "direct";

    XConfigGen::Xray::RulesItem4Ray directCNDNSDomainRule;
    directCNDNSDomainRule.type = "field";
    directCNDNSDomainRule.domain = {
        "domain:alidns.com",
        "domain:doh.pub",
        "domain:dot.pub",
        "domain:360.cn",
        "domain:onedns.net"};
    directCNDNSDomainRule.outboundTag = "direct";

    XConfigGen::Xray::RulesItem4Ray directCNIPRule;
    directCNIPRule.type = "field";
    directCNIPRule.ip = {
        "geoip:cn"};
    directCNIPRule.outboundTag = "direct";

    XConfigGen::Xray::RulesItem4Ray directCNDomainRule;
    directCNDomainRule.type = "field";
    directCNDomainRule.domain = {
        "geosite:cn"};
    directCNDomainRule.outboundTag = "direct";

    xrayConfig.routing.rules = {
        apiRule,
        proxyDomainRule,
        blockQuicRule,
        blockAdsRule,
        directPrivateIPRule,
        directLocalDomainRule,
        directCNDNSRule,
        directCNDNSDomainRule,
        directCNIPRule,
        directCNDomainRule};

    XConfigGen::Xray::Metrics4Ray metrics;
    metrics.tag = "api";

    xrayConfig.metrics = metrics;

    XConfigGen::Xray::Policy4Ray policy;
    policy.system.statsOutboundUplink = true;
    policy.system.statsOutboundDownlink = true;

    xrayConfig.policy = policy;
    xrayConfig.stats = {};

    return xrayConfig;
}

int main()
{
    const auto configJson = generateConfig().toJson();
    XConfigGen::Xray::XrayConfig importXrayConfig;
    importXrayConfig.fromJson(configJson);
    const auto importConfig = importXrayConfig.toJson();
    qDebug().noquote() << configJson << importConfig << (configJson == importConfig);

    const QString uri = QStringLiteral("vless://e1685d45-f1f1-4edc-b0f4-f4ba1483ac89@31.59.111.17:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.aliyun.com&fp=chrome&pbk=111&sid=111&type=tcp&headerType=none#%E9%98%BF%E9%87%8C%E4%BA%91_%E5%9B%BD%E5%86%85_vless");
    QString alias, errMessage;
    const auto outbound = XConfigGen::Xray::Deserialize(uri, alias, errMessage);
    const auto importUri = XConfigGen::Xray::Serialize(outbound, alias);
    qDebug().noquote() << uri << alias << errMessage;
    qDebug().noquote() << outbound.toRawJson();
    qDebug() << importUri;
}
