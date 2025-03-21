#pragma once

#include <QSerializer>

namespace XConfigGen
{

namespace Xray
{

class Log4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, access)
    QS_FIELD_OPT(QString, error)
    QS_FIELD_OPT(QString, loglevel)
};

// inbounds

class Sniffing4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(bool, enabled)
    QS_COLLECTION(QList, QString, destOverride)
    QS_FIELD(bool, routeOnly)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(destOverride)
};

class UsersItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, id)
    QS_FIELD_OPT(int, alterId)
    QS_FIELD_OPT(QString, email)
    QS_FIELD_OPT(QString, security)
    QS_FIELD_OPT(QString, encryption)
    QS_FIELD_OPT(QString, flow)
};

class AccountsItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, user)
    QS_FIELD(QString, pass)
};

class InboundSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, auth)
    QS_FIELD_OPT(bool, udp)
    QS_FIELD_OPT(QString, ip)
    QS_FIELD_OPT(QString, address)
    QS_COLLECTION_OBJECTS(QList, UsersItem4Ray, clients)
    QS_FIELD_OPT(QString, decryption)
    QS_FIELD_OPT(bool, allowTransparent)
    QS_COLLECTION_OBJECTS(QList, AccountsItem4Ray, accounts)
};

class Inbounds4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, tag)
    QS_FIELD(int, port)
    QS_FIELD(QString, listen)
    QS_FIELD(QString, protocol)
    QS_OBJECT(Sniffing4Ray, sniffing)
    QS_OBJECT(InboundSettings4Ray, settings)
};

// StreamSettings

class TlsSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(bool, allowInsecure)
    QS_FIELD_OPT(bool, disableSystemRoot)
    QS_FIELD_OPT(QString, serverName)
    QS_COLLECTION(QList, QString, alpn)
    QS_FIELD_OPT(QString, fingerprint)
    QS_FIELD_OPT(bool, show)
    QS_FIELD_OPT(QString, publicKey)
    QS_FIELD_OPT(QString, shortId)
    QS_FIELD_OPT(QString, spiderX)
    QS_FIELD_OPT(bool, enableSessionResumptionCB)
};

class Header4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, type)
    QS_FIELD_OPT(QString, request)
    QS_FIELD_OPT(QString, response)
    QS_FIELD_OPT(QString, domain)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(request)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(response)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(domain)
};

class TcpSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_OBJECT(Header4Ray, header)
};

class KcpSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(int, mtu)
    QS_FIELD_OPT(int, tti)
    QS_FIELD_OPT(int, uplinkCapacity)
    QS_FIELD_OPT(int, downlinkCapacity)
    QS_FIELD_OPT(bool, congestion)
    QS_FIELD_OPT(int, readBufferSize)
    QS_FIELD_OPT(int, writeBufferSize)
    QS_OBJECT_OPT(Header4Ray, header)
    QS_FIELD_OPT(QString, seed)
};

class WsSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, path)
    QS_FIELD_OPT(QString, host)
    // 仅客户端，自定义 HTTP 头，一个键值对，每个键表示一个 HTTP 头的名称，对应的值是字符串。
    // v2rayN 使用 Headers4Ray { Host; UserAgent}
    QS_QT_DICT(QMap, QString, QString, headers)
    QS_FIELD_OPT(bool, acceptProxyProtocol)
    QS_FIELD_OPT(int, heartbeatPeriod)
};

class HttpUpgradeSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, path)
    QS_FIELD_OPT(QString, host)
};

class XhttpSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, path)
    QS_FIELD_OPT(QString, host)
    QS_FIELD_OPT(QString, mode)

public:
    QJsonObject extra;
    QJsonObject toJson() const override
    {
        auto json = this->QSerializer::toJson();
        json.insert("extra", extra);
        return json;
    }
    void fromJson(const QJsonValue &val) override
    {
        this->QSerializer::fromJson(val);
        extra = val.toObject().value("extra").toObject();
    }
};

class HttpSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, path)
    QS_COLLECTION(QList, QString, host)
    QS_FIELD_OPT(QString, method)
};

class QuicSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, security)
    QS_FIELD_OPT(QString, key)
    QS_OBJECT_OPT(Header4Ray, header)
};

class GrpcSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, authority)
    QS_FIELD_OPT(QString, serviceName)
    QS_FIELD(bool, multiMode)
    QS_FIELD_OPT(int, idle_timeout)
    QS_FIELD_OPT(int, health_check_timeout)
    QS_FIELD_OPT(bool, permit_without_stream)
    QS_FIELD_OPT(int, initial_windows_size)
};

class CustomSockopt4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, type)
    QS_FIELD_OPT(QString, level)
    QS_FIELD_OPT(QString, opt)
    QS_FIELD_OPT(QString, value)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(level)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(opt)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(value)
};

class Sockopt4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(int, mark)
    QS_FIELD_OPT(int, tcpMaxSeg)
    QS_FIELD_OPT(bool, tcpFastOpen)
    QS_FIELD_OPT(QString, tproxy)
    QS_FIELD_OPT(QString, domainStrategy)
    QS_FIELD_OPT(QString, dialerProxy)
    QS_FIELD_OPT(bool, acceptProxyProtocol)
    QS_FIELD_OPT(int, tcpKeepAliveInterval)
    QS_FIELD_OPT(int, tcpKeepAliveIdle)
    QS_FIELD_OPT(int, tcpUserTimeout)
    QS_FIELD_OPT(QString, tcpcongestion)
    QS_FIELD_OPT(QString, interface)
    QS_FIELD_OPT(bool, V6Only)
    QS_FIELD_OPT(int, tcpWindowClamp)
    QS_FIELD_OPT(bool, tcpMptcp)
    QS_FIELD_OPT(bool, tcpNoDelay)
    QS_FIELD_OPT(QString, addressPortStrategy)
    QS_COLLECTION_OBJECTS(QList, CustomSockopt4Ray, customSockopt)
};

class StreamSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, network)
    QS_FIELD_OPT(QString, security)
    QS_OBJECT_OPT(TlsSettings4Ray, tlsSettings)
    QS_OBJECT_OPT(TcpSettings4Ray, tcpSettings)
    QS_OBJECT_OPT(KcpSettings4Ray, kcpSettings)
    QS_OBJECT_OPT(WsSettings4Ray, wsSettings)
    QS_OBJECT_OPT(HttpUpgradeSettings4Ray, httpupgradeSettings)
    QS_OBJECT_OPT(XhttpSettings4Ray, xhttpSettings)
    QS_OBJECT_OPT(HttpSettings4Ray, httpSettings)
    QS_OBJECT_OPT(QuicSettings4Ray, quicSettings)
    QS_OBJECT_OPT(GrpcSettings4Ray, grpcSettings)
    QS_OBJECT_OPT(TlsSettings4Ray, realitySettings)
    QS_OBJECT_OPT(Sockopt4Ray, sockopt)
};

// outbounds

class VnextItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, address)
    QS_FIELD(int, port)
    QS_COLLECTION_OBJECTS(QList, UsersItem4Ray, users)
};

class SocksUsersItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, user)
    QS_FIELD(QString, pass)
    QS_FIELD_OPT(int, level)
    QS_INTERNAL_MEMBER_SKIP_NULL(level)
};

class ServersItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD_OPT(QString, email)
    QS_FIELD(QString, address)
    QS_FIELD_OPT(QString, method)
    QS_FIELD_OPT(bool, ota)
    QS_FIELD_OPT(QString, password)
    QS_FIELD(int, port)
    QS_FIELD_OPT(int, level)
    QS_COLLECTION_OBJECTS(QList, SocksUsersItem4Ray, users)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(email)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(method)
    QS_INTERNAL_MEMBER_SKIP_NULL(ota)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(password)
    QS_INTERNAL_MEMBER_SKIP_NULL(level)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(users)
};

class Mux4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(bool, enabled)
    QS_FIELD_OPT(int, concurrency)
    QS_FIELD_OPT(int, xudpConcurrency)
    QS_FIELD_OPT(QString, xudpProxyUDP443)
    QS_INTERNAL_MEMBER_SKIP_NULL(concurrency)
    QS_INTERNAL_MEMBER_SKIP_NULL(xudpConcurrency)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(xudpProxyUDP443)
};

class Response4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, type)
};

class FragmentItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_INTERNAL_SKIP_EMPTY_AND_NULL_LITERALS
    QS_FIELD_OPT(QString, packets)
    QS_FIELD_OPT(QString, length)
    QS_FIELD_OPT(QString, interval)
};

class OutboundSettings4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_COLLECTION_OBJECTS(QList, VnextItem4Ray, vnext)
    QS_COLLECTION_OBJECTS(QList, ServersItem4Ray, servers)
    QS_OBJECT_OPT(Response4Ray, response)
    QS_FIELD_OPT(QString, domainStrategy)
    QS_FIELD_OPT(int, userLevel)
    QS_COLLECTION_OBJECTS(QList, FragmentItem4Ray, fragment)

    QS_INTERNAL_MEMBER_SKIP_EMPTY(vnext)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(servers)
    QS_INTERNAL_MEMBER_SKIP_NULL(response)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(domainStrategy)
    QS_INTERNAL_MEMBER_SKIP_NULL(userLevel)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(fragment)
};

class Outbounds4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, tag)
    QS_FIELD(QString, protocol)
    QS_OBJECT_OPT(OutboundSettings4Ray, settings)
    QS_OBJECT_OPT(StreamSettings4Ray, streamSettings)
    QS_OBJECT_OPT(Mux4Ray, mux)
    QS_INTERNAL_MEMBER_SKIP_NULL(settings)
    QS_INTERNAL_MEMBER_SKIP_NULL(streamSettings)
    QS_INTERNAL_MEMBER_SKIP_NULL(mux)
};

// dns

class DnsServers4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, address)
    QS_FIELD_OPT(int, port)
    QS_COLLECTION(QList, QString, domains)
    QS_COLLECTION(QList, QString, expectIPs)
    QS_FIELD_OPT(bool, skipFallback)
    QS_FIELD_OPT(QString, clientIP)
    QS_FIELD_OPT(QString, queryStrategy)
    QS_INTERNAL_MEMBER_SKIP_NULL(port)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(domains)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(expectIPs)
    QS_INTERNAL_MEMBER_SKIP_NULL(skipFallback)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(clientIP)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(queryStrategy)
};

class Dns4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD_OPT(QString, clientIP)
    QS_FIELD_OPT(QString, queryStrategy)
    QS_FIELD_OPT(bool, disableCache)
    QS_FIELD_OPT(bool, disableFallback)
    QS_FIELD_OPT(bool, disableFallbackIfMatch)
    QS_FIELD_OPT(QString, tag)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(clientIP)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(queryStrategy)
    QS_INTERNAL_MEMBER_SKIP_NULL(disableCache)
    QS_INTERNAL_MEMBER_SKIP_NULL(disableFallback)
    QS_INTERNAL_MEMBER_SKIP_NULL(disableFallbackIfMatch)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(tag)

public:
    QMap<QString, QVariant> hosts;
    QList<QVariant> servers;
    QJsonObject toJson() const override
    {
        QJsonObject hostsObject;
        for (auto it = hosts.begin(); it != hosts.end(); ++it)
        {
            if (it.value().metaType().id() == QMetaType::QStringList)
            {
                QJsonArray arr;
                for (auto &item : it.value().toStringList())
                {
                    arr.append(item);
                }
                hostsObject.insert(it.key(), arr);
            }
            else
            {
                hostsObject.insert(it.key(), it.value().toString());
            }
        }
        QJsonArray serversArray;
        for (const auto &it : servers)
        {
            if (it.canConvert<DnsServers4Ray>())
            {
                serversArray.append(it.value<DnsServers4Ray>().toJson());
            }
            else
            {
                serversArray.append(it.toString());
            }
        }
        auto json = this->QSerializer::toJson();
        json.insert("hosts", hostsObject);
        json.insert("servers", serversArray);
        return json;
    }
    void fromJson(const QJsonValue &val) override
    {
        this->QSerializer::fromJson(val);
        hosts.clear();
        servers.clear();
        auto obj = val.toObject();
        for (auto it = obj.begin(); it != obj.end(); ++it)
        {
            if (it.key() == "hosts")
            {
                auto hostsObject = it.value().toObject();
                for (auto it2 = hostsObject.begin(); it2 != hostsObject.end(); ++it2)
                {
                    if (it2.value().isArray())
                    {
                        const auto &array = it2.value().toArray();
                        QStringList arr;
                        for (const auto &item : array)
                        {
                            arr.append(item.toString());
                        }
                        hosts.insert(it2.key(), arr);
                    }
                    else
                    {
                        hosts.insert(it2.key(), it2.value().toString());
                    }
                }
            }
            else if (it.key() == "servers")
            {
                const auto &array = it.value().toArray();
                for (const auto &item : array)
                {
                    if (item.isObject())
                    {
                        DnsServers4Ray server;
                        server.fromJson(item);
                        servers.append(QVariant::fromValue(server));
                    }
                    else
                    {
                        servers.append(item.toString());
                    }
                }
            }
        }
    }
};

class FakeDNS4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD_DEFAULT(QString, ipPool, QStringLiteral("198.18.0.0/16"))
    QS_FIELD_DEFAULT(int, poolSize, 65535)
};

// routing

class RulesItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD_OPT(QString, type)
    QS_FIELD_OPT(QString, port)
    QS_FIELD_OPT(QString, network)
    QS_COLLECTION(QList, QString, inboundTag)
    QS_FIELD_OPT(QString, outboundTag)
    QS_FIELD_OPT(QString, balancerTag)
    QS_COLLECTION(QList, QString, ip)
    QS_COLLECTION(QList, QString, domain)
    QS_COLLECTION(QList, QString, protocol)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(type)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(port)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(network)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(inboundTag)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(outboundTag)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(balancerTag)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(ip)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(domain)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(protocol)
};

class BalancersStrategy4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD_OPT(QString, type)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(type)
};

class BalancersItem4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_COLLECTION(QList, QString, selector)
    QS_OBJECT_OPT(BalancersStrategy4Ray, strategy)
    QS_FIELD_OPT(QString, tag)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(selector)
    QS_INTERNAL_MEMBER_SKIP_NULL(strategy)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(tag)
};

class Routing4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, domainStrategy)
    QS_FIELD_OPT(QString, domainMatcher)
    QS_COLLECTION_OBJECTS(QList, RulesItem4Ray, rules)
    QS_COLLECTION_OBJECTS(QList, BalancersItem4Ray, balancers)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(domainMatcher)
    QS_INTERNAL_MEMBER_SKIP_EMPTY(balancers)
};

class SystemPolicy4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(bool, statsOutboundUplink)
    QS_FIELD(bool, statsOutboundDownlink)
};

class Policy4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_OBJECT(SystemPolicy4Ray, system)
};

class Metrics4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_FIELD(QString, tag)
};

class Stats4Ray : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
};

class XrayConfig : public QSerializer
{
    Q_GADGET
    QS_SERIALIZABLE
    QS_OBJECT(Log4Ray, log)
    QS_OBJECT(Dns4Ray, dns)
    QS_OBJECT_OPT(FakeDNS4Ray, fakeDNS)
    QS_COLLECTION_OBJECTS(QList, Inbounds4Ray, inbounds)
    QS_COLLECTION_OBJECTS(QList, Outbounds4Ray, outbounds)
    QS_OBJECT(Routing4Ray, routing)
    QS_OBJECT_OPT(Metrics4Ray, metrics)
    QS_OBJECT_OPT(Policy4Ray, policy)
    QS_OBJECT_OPT(Stats4Ray, stats)
    QS_FIELD_OPT(QString, remarks)
    QS_INTERNAL_MEMBER_SKIP_NULL(fakeDNS)
    QS_INTERNAL_MEMBER_SKIP_NULL(metrics)
    QS_INTERNAL_MEMBER_SKIP_NULL(policy)
    QS_INTERNAL_MEMBER_SKIP_NULL(stats)
    QS_INTERNAL_MEMBER_SKIP_EMPTY_AND_NULL_LITERALS(remarks)

public:
    QList<FakeDNS4Ray> fakeDNSList;
    QJsonObject toJson() const override
    {
        auto json = this->QSerializer::toJson();
        if (!fakeDNSList.isEmpty())
        {
            if (fakeDNS.has_value())
                qWarning() << "fakeDNSList has been set, fakeDNS will be overridden.";
            QJsonArray fakeDNSArray;
            for (const auto &item : fakeDNSList)
            {
                fakeDNSArray.append(item.toJson());
            }
            json.insert("fakedns", fakeDNSArray);
        }
        return json;
    }
    void fromJson(const QJsonValue &val) override
    {
        this->QSerializer::fromJson(val);
        if (val.isObject())
        {
            auto obj = val.toObject();
            if (obj.contains("fakedns"))
            {
                const auto fakednsItem = obj.value("fakedns");
                if (fakednsItem.isArray())
                {
                    fakeDNSList.clear();
                    auto fakeDNSArray = fakednsItem.toArray();
                    for (const auto &item : std::as_const(fakeDNSArray))
                    {
                        FakeDNS4Ray fakeDNS;
                        fakeDNS.fromJson(item);
                        fakeDNSList.append(fakeDNS);
                    }
                }
                else if (fakednsItem.isObject())
                {
                    FakeDNS4Ray fakeDNS;
                    fakeDNS.fromJson(fakednsItem);
                }
            }
        }
    }
};

} // namespace Xray

} // namespace XConfigGen
