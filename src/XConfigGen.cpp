#include "XConfigGen.h"

#include <QRandomGenerator>
#include <QUrlQuery>

std::optional<QString> XConfigGen::Common::SafeBase64Decode(QString string)
{
    QByteArray ba = string.replace(QChar('-'), QChar('+')).replace(QChar('_'), QChar('/')).toUtf8();
    return Base64Decode(ba);
}

QString XConfigGen::Common::SafeBase64Encode(const QString &string, bool trim)
{
    QByteArray base64 = string.toUtf8().toBase64();
    base64.replace('+', '-').replace('/', '_');

    if (trim)
    {
        while (base64.endsWith('='))
        {
            base64.chop(1);
        }
    }

    return QString::fromUtf8(base64);
}

QString XConfigGen::Common::Base64Encode(const QString &string)
{
    return string.toUtf8().toBase64();
}

std::optional<QString> XConfigGen::Common::Base64Decode(const QString &string)
{
    const auto result = QByteArray::fromBase64Encoding(string.toUtf8(), QByteArray::Base64Option::OmitTrailingEquals);
    if (result.decodingStatus == QByteArray::Base64DecodingStatus::Ok)
        return QString(result.decoded);
    return std::nullopt;
}

QString XConfigGen::Common::JsonToString(const QJsonObject &json, QJsonDocument::JsonFormat format)
{
    QJsonDocument doc;
    doc.setObject(json);
    return doc.toJson(format);
}

QString XConfigGen::Common::JsonToString(const QJsonArray &array, QJsonDocument::JsonFormat format)
{
    QJsonDocument doc;
    doc.setArray(array);
    return doc.toJson(format);
}

QString XConfigGen::Common::VerifyJsonString(const QString &source)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(source.toUtf8(), &error);
    Q_UNUSED(doc)

    if (error.error == QJsonParseError::NoError)
    {
        return {};
    }
    else
    {
        return error.errorString();
    }
}

QStringList XConfigGen::Common::SplitLines(const QString &_string)
{
    static const QRegularExpression regex("[\r\n]");
    return _string.split(regex, Qt::SplitBehaviorFlags::SkipEmptyParts);
}

const QString XConfigGen::Common::GenerateRandomString(int len)
{
    const QString possibleCharacters(QStringLiteral("abcdefghijklmnopqrstuvwxyz"));
    const int max = possibleCharacters.length();
    QRandomGenerator *generator = QRandomGenerator::system();
    QString randomString;

    if (len <= 0)
    {
        return randomString;
    }

    randomString.reserve(len);
    for (int i = 0; i < len; ++i)
    {
        int index = generator->bounded(max);
        QChar nextChar = possibleCharacters[index];
        randomString.append(nextChar);
    }

    return randomString;
}

XConfigGen::Xray::Outbounds4Ray XConfigGen::Xray::Deserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag)
{
    Outbounds4Ray outbound;

    const QMap<QString, QString> protocols {
        {QStringLiteral("vless"),  QStringLiteral("vless")      },
        {QStringLiteral("vmess"),  QStringLiteral("vmess")      },
        {QStringLiteral("trojan"), QStringLiteral("trojan")     },
        {QStringLiteral("ss"),     QStringLiteral("shadowsocks")}
    };

    bool protocolsMatched = false;
    QString matchedProtocol;
    for (auto it = protocols.begin(); it != protocols.end(); ++it)
    {
        if (uri.startsWith(QString(it.key()).append(QStringLiteral("://"))))
        {
            protocolsMatched = true;
            matchedProtocol = it.value();
            break;
        }
    }

    if (!protocolsMatched)
    {
        errMessage = QObject::tr("unsupported protocol");
        return Outbounds4Ray();
    }
    else if (matchedProtocol == QStringLiteral("vmess") && (!uri.contains(QStringLiteral("@"))))
    {
        return VmessJsonDeserialize(uri, alias, errMessage, tag);
    }

    outbound.protocol = matchedProtocol;

    QUrl url(uri);
    if (!url.isValid())
    {
        errMessage = QObject::tr("link parse failed: %1").arg(url.errorString());
        return Outbounds4Ray();
    }

    // fetch host
    const auto hostRaw = url.host();
    if (hostRaw.isEmpty())
    {
        errMessage = QObject::tr("empty host");
        return Outbounds4Ray();
    }
    const auto host = (hostRaw.startsWith('[') && hostRaw.endsWith(']')) ? hostRaw.mid(1, hostRaw.length() - 2) : hostRaw;

    // fetch port
    const auto port = url.port();
    if (port == -1)
    {
        errMessage = QObject::tr("missing port");
        return Outbounds4Ray();
    }

    // fetch remarks
    const auto remarks = url.fragment();
    if (!remarks.isEmpty())
    {
        alias = remarks;
    }

    // fetch uuid
    const auto uuid = url.userInfo();
    if (uuid.isEmpty())
    {
        errMessage = QObject::tr("missing uuid");
        return Outbounds4Ray();
    }

    QUrlQuery query(url.query());

    StreamSettings4Ray streamSettings;

    // handle type
    const auto hasType = query.hasQueryItem("type");
    const auto type = hasType ? query.queryItemValue("type") : "raw";
    if (type != "raw" || type != "tcp")
        streamSettings.network = type;

    // type-wise settings
    if (type == "kcp")
    {
        KcpSettings4Ray kcpSettings;
        Header4Ray header;
        const auto hasSeed = query.hasQueryItem("seed");
        if (hasSeed)
            kcpSettings.seed = query.queryItemValue("seed");

        const auto hasHeaderType = query.hasQueryItem("headerType");
        const auto headerType = hasHeaderType ? query.queryItemValue("headerType") : "none";
        header.type = headerType;

        // https://github.com/2dust/v2rayN/pull/6852
        // https://github.com/2dust/v2rayNG/pull/4368
        // https://github.com/XTLS/Xray-core/discussions/716#discussioncomment-12387674
        // 目前 mkcp dns 伪装域名使用 host 字段

        const auto hasHost = query.hasQueryItem("host");
        if (hasHost)
            header.domain = QUrl::fromPercentEncoding(query.queryItemValue("host").toUtf8());

        kcpSettings.header = header;
        streamSettings.kcpSettings = kcpSettings;
    }
    else if (type == "raw" || type == "tcp")
    {
        // url not support http header
        // https://github.com/XTLS/Xray-core/discussions/716
        // TcpSettings4Ray tcpSettings;
        // Header4Ray header;

        // header.type = "none";
        // tcpSettings.header = header;
        // streamSettings.tcpSettings = tcpSettings;
    }
    else if (type == "ws")
    {
        WsSettings4Ray wsSettings;

        const auto hasPath = query.hasQueryItem("path");
        const auto path = hasPath ? QUrl::fromPercentEncoding(query.queryItemValue("path").toUtf8()) : "/";
        if (path != "/")
            wsSettings.path = path;

        const auto hasHost = query.hasQueryItem("host");
        if (hasHost)
            wsSettings.host = QUrl::fromPercentEncoding(query.queryItemValue("host").toUtf8());

        streamSettings.wsSettings = wsSettings;
    }
    else if (type == "quic")
    {
        QuicSettings4Ray quicSettings;
        const auto hasQuicSecurity = query.hasQueryItem("quicSecurity");
        if (hasQuicSecurity)
        {
            const auto quicSecurity = query.queryItemValue("quicSecurity");
            quicSettings.security = quicSecurity;

            if (quicSecurity != "none")
            {
                const auto key = query.queryItemValue("key");
                quicSettings.key = key;
            }

            const auto hasHeaderType = query.hasQueryItem("headerType");
            const auto headerType = hasHeaderType ? query.queryItemValue("headerType") : "none";
            Header4Ray header;
            header.type = headerType;
            quicSettings.header = header;
        }
        streamSettings.quicSettings = quicSettings;
    }
    else if (type == "grpc")
    {
        GrpcSettings4Ray grpcSettings;
        const auto hasServiceName = query.hasQueryItem("serviceName");
        if (hasServiceName)
            grpcSettings.serviceName = QUrl::fromPercentEncoding(query.queryItemValue("serviceName").toUtf8());

        const auto hasMode = query.hasQueryItem("mode");
        if (hasMode)
            grpcSettings.multiMode = QUrl::fromPercentEncoding(query.queryItemValue("mode").toUtf8()) == "multi";

        const auto hasAuthority = query.hasQueryItem("authority");
        if (hasAuthority)
            grpcSettings.authority = QUrl::fromPercentEncoding(query.queryItemValue("authority").toUtf8());

        streamSettings.grpcSettings = grpcSettings;
    }
    else if (type == "httpupgrade")
    {
        HttpUpgradeSettings4Ray httpUpgradeSettings;
        const auto hasPath = query.hasQueryItem("path");
        const auto path = hasPath ? QUrl::fromPercentEncoding(query.queryItemValue("path").toUtf8()) : "/";
        if (path != "/")
            httpUpgradeSettings.path = path;

        const auto hasHost = query.hasQueryItem("host");
        if (hasHost)
            httpUpgradeSettings.host = QUrl::fromPercentEncoding(query.queryItemValue("host").toUtf8());

        streamSettings.httpupgradeSettings = httpUpgradeSettings;
    }
    else if (type == "xhttp")
    {
        XhttpSettings4Ray xhttpSettings;
        const auto hasPath = query.hasQueryItem("path");
        const auto path = hasPath ? QUrl::fromPercentEncoding(query.queryItemValue("path").toUtf8()) : "/";
        if (path != "/")
            xhttpSettings.path = path;

        const auto hasHost = query.hasQueryItem("host");
        if (hasHost)
            xhttpSettings.host = QUrl::fromPercentEncoding(query.queryItemValue("host").toUtf8());

        const auto hasMode = query.hasQueryItem("mode");
        if (hasMode)
            xhttpSettings.mode = QUrl::fromPercentEncoding(query.queryItemValue("mode").toUtf8());

        const auto hasExtra = query.hasQueryItem("extra");
        if (hasExtra)
            xhttpSettings.extra = QJsonDocument::fromJson(QUrl::fromPercentEncoding(query.queryItemValue("extra").toUtf8()).toUtf8()).object();
    }

    // tls/reality-wise settings
    const auto hasSecurity = query.hasQueryItem("security");
    const auto security = hasSecurity ? query.queryItemValue("security") : "none";

    TlsSettings4Ray tlsSettings;

    streamSettings.security = security;
    // sni
    const auto hasSNI = query.hasQueryItem("sni");
    if (hasSNI)
    {
        const auto sni = query.queryItemValue("sni");
        tlsSettings.serverName = sni;
    }
    // fingerprint
    const auto hasFingerprint = query.hasQueryItem("fp");
    if (hasFingerprint)
    {
        const auto fingerprint = query.queryItemValue("fp");
        tlsSettings.fingerprint = fingerprint;
    }

    // reality-specific
    if (security == "reality")
    {
        const auto publicKey = query.queryItemValue("pbk");
        if (publicKey.isEmpty())
        {
            errMessage = QObject::tr("missing publicKey");
            return Outbounds4Ray();
        }
        tlsSettings.publicKey = publicKey;

        const auto hasShortId = query.hasQueryItem("sid");
        if (hasShortId)
        {
            const auto shortId = query.queryItemValue("sid");
            tlsSettings.shortId = shortId;
        }

        const auto hasSpiderX = query.hasQueryItem("spx");
        if (hasSpiderX)
        {
            // 使用 URIComponent 转义
            const auto spiderX = QUrl::fromPercentEncoding(query.queryItemValue("spx").toUtf8());
            tlsSettings.spiderX = spiderX;
        }
        streamSettings.realitySettings = tlsSettings;
    }
    else // tls-specific
    {
        const auto hasALPN = query.hasQueryItem("alpn");
        if (hasALPN)
        {
            const auto alpnRaw = QUrl::fromPercentEncoding(query.queryItemValue("alpn").toUtf8());
            const auto alpnArray = alpnRaw.split(",");
            tlsSettings.alpn = alpnArray;
        }
        // 理论：没有 allowInsecure 这个字段。不安全的节点，不适合分享。
        const auto hasAllowInsecure = query.hasQueryItem("allowInsecure");
        if (hasAllowInsecure)
        {
            const auto allowInsecure = query.queryItemValue("allowInsecure") == "1";
            tlsSettings.allowInsecure = allowInsecure;
        }
        streamSettings.tlsSettings = tlsSettings;
    }

    OutboundSettings4Ray outboundSettings;

    if (matchedProtocol == QStringLiteral("vless"))
    {
        const auto encryption = query.hasQueryItem("encryption") ? query.queryItemValue("encryption") : QStringLiteral("auto");
        VnextItem4Ray vnext;
        vnext.address = host;
        vnext.port = port;
        UsersItem4Ray user;
        user.id = uuid;
        if (encryption == QStringLiteral("none"))
        {
            user.encryption = encryption;
        }
        if (query.hasQueryItem(QStringLiteral("flow")))
            user.flow = query.queryItemValue(QStringLiteral("flow"));
        vnext.users = {user};
        outboundSettings.vnext = {vnext};
    }
    else
    {
        ServersItem4Ray server;
        server.address = host;
        server.port = port;
        server.password = uuid;
        outboundSettings.servers = {server};
    }

    outbound.settings = outboundSettings;

    outbound.streamSettings = streamSettings;

    return outbound;
}

XConfigGen::Xray::Outbounds4Ray XConfigGen::Xray::VmessJsonDeserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag)
{
    const auto vmess = uri.trimmed();
    const auto b64Str = vmess.mid(8, vmess.length() - 8);
    const auto vmessJsonStr = Common::SafeBase64Decode(b64Str);
    const QJsonObject vmessJson = QJsonDocument::fromJson(vmessJsonStr.value_or(QString()).toUtf8()).object();
    if (vmessJson.isEmpty())
    {
        errMessage = QObject::tr("URI may be invalid or empty");
        return Outbounds4Ray();
    }
    // https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link
    if (!vmessJson.contains(QStringLiteral("v")))
    {
        errMessage = QObject::tr("not supported vmess v1");
        return Outbounds4Ray();
    }
    if (vmessJson.contains(QStringLiteral("ps")))
        alias = vmessJson.value(QStringLiteral("ps")).toString();

    VnextItem4Ray vnext;
    vnext.address = vmessJson.value(QStringLiteral("add")).toString();
    vnext.port = vmessJson.value(QStringLiteral("port")).toString().toInt();
    UsersItem4Ray user;
    user.id = vmessJson.value(QStringLiteral("id")).toString();
    user.alterId = vmessJson.value(QStringLiteral("aid")).toString().toInt();
    user.security = vmessJson.value(QStringLiteral("scy")).toString(QStringLiteral("auto"));
    vnext.users = {user};

    const auto network = vmessJson.value(QStringLiteral("net")).toString();
    const auto security = vmessJson.value(QStringLiteral("tls")).toString();
    // 伪装类型(none/http/srtp/utp/wechat-video/dns) *tcp or kcp or QUIC
    const auto type = vmessJson.value(QStringLiteral("type")).toString();
    const auto host = vmessJson.value(QStringLiteral("host")).toString();
    const auto path = vmessJson.value(QStringLiteral("path")).toString(QStringLiteral("/"));
    const auto alpnStr = vmessJson.value(QStringLiteral("alpn")).toString();
    const auto fingerprint = vmessJson.value(QStringLiteral("fp")).toString();
    const auto sni = vmessJson.value(QStringLiteral("sni")).toString();

    // 拼接为 JsonObject 后，StreamSettings fromJson
    QJsonObject streamSettingsJson;
    streamSettingsJson.insert(QStringLiteral("network"), network);
    streamSettingsJson.insert(QStringLiteral("security"), security);
    if (security == QStringLiteral("tls"))
    {
        QJsonObject tlsSettingsJson;
        tlsSettingsJson.insert(QStringLiteral("fingerprint"), fingerprint);
        if (!alpnStr.isEmpty())
        {
            tlsSettingsJson.insert(QStringLiteral("alpn"), QJsonArray::fromStringList(alpnStr.split(',', Qt::SkipEmptyParts)));
        }
        tlsSettingsJson.insert(QStringLiteral("serverName"), sni);
        streamSettingsJson.insert(QStringLiteral("tlsSettings"), tlsSettingsJson);
    }

    const auto networkSettings = network.toLower().append("Settings");

    QJsonObject networkSettingsJson;
    QJsonObject headerJson;
    if (!host.isEmpty())
    {
        if (network == QStringLiteral("kcp") && type == QStringLiteral("dns"))
        {
            headerJson.insert(QStringLiteral("domain"), host);
        }
        else
            networkSettingsJson.insert(QStringLiteral("host"), host);

        streamSettingsJson.insert(QStringLiteral("networkSettings"), networkSettingsJson);
    }
    if (path != QStringLiteral("/"))
        networkSettingsJson.insert(QStringLiteral("path"), path);
    if (type != QStringLiteral("none"))
        headerJson.insert(QStringLiteral("type"), type);

    networkSettingsJson.insert(QStringLiteral("header"), headerJson);
    streamSettingsJson.insert(networkSettings, networkSettingsJson);

    StreamSettings4Ray streamSettings;
    streamSettings.fromJson(streamSettingsJson);

    Outbounds4Ray outbound;
    outbound.protocol = QStringLiteral("vmess");
    outbound.streamSettings = streamSettings;
    OutboundSettings4Ray outboundSettings;
    outboundSettings.vnext = {vnext};
    outbound.settings = outboundSettings;

    return outbound;
}

const QString XConfigGen::Xray::Serialize(const Outbounds4Ray &outbounds, const QString &alias)
{
    if (outbounds.protocol == QStringLiteral("vmess"))
        return VmessJsonSerialize(outbounds, alias);

    const QMap<QString, QString> protocols {
        {QStringLiteral("vless"),       QStringLiteral("vless") },
        {QStringLiteral("trojan"),      QStringLiteral("trojan")},
        {QStringLiteral("shadowsocks"), QStringLiteral("ss")    }
    };

    QString serverAddress;

    QUrl url;
    QUrlQuery query;
    url.setScheme(protocols.value(outbounds.protocol));
    url.setFragment(alias);

    if (outbounds.protocol == QStringLiteral("vless"))
    {
        const auto &server = outbounds.settings->vnext.constFirst();
        url.setHost(server.address);
        url.setPort(server.port);
        url.setUserInfo(server.users.constFirst().id.value());
        serverAddress = server.address;
        if (server.users.constFirst().encryption.has_value())
        {
            query.addQueryItem("encryption", server.users.constFirst().encryption.value());
        }
        if (server.users.constFirst().flow.has_value())
        {
            query.addQueryItem("flow", server.users.constFirst().flow.value());
        }
    }
    else
    {
        const auto &server = outbounds.settings->servers.constFirst();
        url.setHost(server.address);
        url.setPort(server.port);
        url.setUserInfo(server.password.value());
        serverAddress = server.address;
    }

    if (!outbounds.streamSettings.has_value())
    {
        return url.toString();
    }

    const auto &streamSettings = outbounds.streamSettings.value();
    const auto network = streamSettings.network.value_or(QStringLiteral("tcp"));

    if (network == QStringLiteral("kcp") && streamSettings.kcpSettings.has_value())
    {
        const auto &kcpSettings = streamSettings.kcpSettings.value();
        if (kcpSettings.seed.has_value())
            query.addQueryItem("seed", kcpSettings.seed.value());
        if (kcpSettings.header.has_value())
        {
            const auto &header = kcpSettings.header.value();
            query.addQueryItem("headerType", header.type);
            if (header.domain.has_value())
                query.addQueryItem("host", header.domain.value());
        }
    }
    else if (streamSettings.tcpSettings.has_value() && (network == QStringLiteral("raw") || network == QStringLiteral("tcp")))
    {
        const auto &tcpSettings = streamSettings.tcpSettings.value();
        query.addQueryItem("headerType", tcpSettings.header.type);
    }
    else if (network == QStringLiteral("ws"))
    {
        const auto &wsSettings = streamSettings.wsSettings.value_or(WsSettings4Ray());
        query.addQueryItem("path", wsSettings.path.value_or(QStringLiteral("/")));
        query.addQueryItem("host", wsSettings.host.value_or(serverAddress));
    }
    // else if (network == QStringLiteral("quic"))
    // {
    //     const auto &quicSettings = streamSettings.quicSettings.value_or(QuicSettings4Ray());
    //     query.addQueryItem("quicSecurity", quicSettings.security.value_or(QStringLiteral("none")));
    //     if (quicSettings.security != QStringLiteral("none"))
    //     {
    //         query.addQueryItem("key", quicSettings.key.value_or(QString()));
    //     }
    //     if (quicSettings.header.has_value())
    //     {
    //         const auto &header = quicSettings.header.value();
    //         query.addQueryItem("headerType", header.type);
    //     }
    // }
    else if (network == QStringLiteral("grpc"))
    {
        const auto &grpcSettings = streamSettings.grpcSettings.value_or(GrpcSettings4Ray());
        query.addQueryItem("serviceName", grpcSettings.serviceName.value_or(serverAddress));
        query.addQueryItem("mode", grpcSettings.multiMode ? "multi" : "single");
    }
    else if (network == QStringLiteral("httpupgrade"))
    {
        const auto &httpUpgradeSettings = streamSettings.httpupgradeSettings.value_or(HttpUpgradeSettings4Ray());
        query.addQueryItem("path", httpUpgradeSettings.path.value_or(QStringLiteral("/")));
        query.addQueryItem("host", httpUpgradeSettings.host.value_or(serverAddress));
    }
    else if (network == QStringLiteral("xhttp"))
    {
        const auto &xhttpSettings = streamSettings.xhttpSettings.value_or(XhttpSettings4Ray());
        query.addQueryItem("path", xhttpSettings.path.value_or(QStringLiteral("/")));
        query.addQueryItem("host", xhttpSettings.host.value_or(serverAddress));
        query.addQueryItem("mode", xhttpSettings.mode.value_or(QStringLiteral("http")));
        query.addQueryItem("extra", QUrl::toPercentEncoding(QJsonDocument(xhttpSettings.extra).toJson()));
    }

    query.addQueryItem("security", streamSettings.security.value_or(QStringLiteral("none")));
    if (streamSettings.security != QStringLiteral("none"))
    {
        if (streamSettings.security == QStringLiteral("reality") && streamSettings.realitySettings.has_value())
        {
            const auto &tlsSettings = streamSettings.realitySettings.value();
            query.addQueryItem("sni", tlsSettings.serverName.value_or(serverAddress));
            if (tlsSettings.fingerprint.has_value())
                query.addQueryItem("fp", tlsSettings.fingerprint.value());
            query.addQueryItem("pbk", tlsSettings.publicKey.value());
            if (tlsSettings.shortId.has_value())
                query.addQueryItem("sid", tlsSettings.shortId.value());
            if (tlsSettings.spiderX.has_value())
                query.addQueryItem("spx", QUrl::toPercentEncoding(tlsSettings.spiderX.value()));
        }
        else if (streamSettings.tlsSettings.has_value())
        {
            const auto &tlsSettings = streamSettings.tlsSettings.value();
            query.addQueryItem("sni", tlsSettings.serverName.value_or(serverAddress));
            if (tlsSettings.fingerprint.has_value())
                query.addQueryItem("fp", tlsSettings.fingerprint.value());
            if (!tlsSettings.alpn.isEmpty())
                query.addQueryItem("alpn", tlsSettings.alpn.join(','));
            if (tlsSettings.allowInsecure.has_value())
                query.addQueryItem("allowInsecure", tlsSettings.allowInsecure ? "1" : "0");
        }
    }

    url.setQuery(query);

    return url.toEncoded();
}

const QString XConfigGen::Xray::VmessJsonSerialize(const Outbounds4Ray &outbounds, const QString &alias)
{
    QJsonObject vmessUriRoot;
    vmessUriRoot["v"] = 2;
    vmessUriRoot["ps"] = alias;
    const auto &settings = outbounds.settings->vnext.constFirst();
    vmessUriRoot["add"] = settings.address;
    const auto &user = settings.users.constFirst();
    vmessUriRoot["id"] = user.id.value();
    vmessUriRoot["aid"] = QString::number(user.alterId.value_or(0));
    vmessUriRoot["scy"] = user.security.value_or(QStringLiteral("auto"));
    const auto &streamSettings = outbounds.streamSettings.value();
    const auto network = streamSettings.network.value_or(QStringLiteral("tcp"));
    vmessUriRoot["net"] = network;
    // host: 伪装的域名
    // http(tcp)->host中间逗号(,)隔开
    // ws->host
    // h2->host
    // QUIC->securty

    // path: path
    // ws->path
    // h2->path
    // QUIC->key/Kcp->seed
    // grpc->serviceName
    if (streamSettings.tcpSettings.has_value() && (network == QStringLiteral("tcp") || network == QStringLiteral("raw")))
    {
        const auto type = streamSettings.tcpSettings->header.type;
        vmessUriRoot["type"] = type.isEmpty() ? QStringLiteral("none") : type;
    }
    else if (streamSettings.kcpSettings.has_value() && network == QStringLiteral("kcp"))
    {
        const auto &kcpSettings = streamSettings.kcpSettings.value();
        vmessUriRoot["type"] = kcpSettings.header->type;
        vmessUriRoot["path"] = kcpSettings.seed.value_or(QString());
        if (kcpSettings.header.has_value() && kcpSettings.header->domain.has_value())
            vmessUriRoot["host"] = kcpSettings.header->domain.value();
        else
            vmessUriRoot["host"] = QString();
    }
    else if (streamSettings.quicSettings.has_value() && network == QStringLiteral("quic"))
    {
        const auto &quicSettings = streamSettings.quicSettings.value();
        vmessUriRoot["type"] = quicSettings.header->type;
        vmessUriRoot["host"] = quicSettings.security.value_or(QString());
        vmessUriRoot["path"] = quicSettings.key.value_or(QString());
    }
    else if (streamSettings.wsSettings.has_value() && network == QStringLiteral("ws"))
    {
        const auto &wsSettings = streamSettings.wsSettings.value();
        if (wsSettings.headers.contains(QStringLiteral("Host")))
            vmessUriRoot["host"] = wsSettings.headers.value(QStringLiteral("Host"));
        else
            vmessUriRoot["host"] = settings.address;
        vmessUriRoot["path"] = wsSettings.path.value_or(QStringLiteral("/"));
    }
    else if (network == QStringLiteral("grpc"))
    {
        const auto &grpcSettings = streamSettings.grpcSettings.value_or(GrpcSettings4Ray());
        vmessUriRoot["path"] = grpcSettings.serviceName.value_or(settings.address);
    }
    const auto security = streamSettings.security.value_or(QStringLiteral("none"));
    if (streamSettings.tlsSettings.has_value() && security == QStringLiteral("tls"))
    {
        const auto &tlsSettings = streamSettings.tlsSettings.value();
        if (!tlsSettings.fingerprint.value().isEmpty())
            vmessUriRoot["fp"] = tlsSettings.fingerprint.value();
        if (!tlsSettings.serverName.value().isEmpty())
            vmessUriRoot["sni"] = tlsSettings.serverName.value();
        if (!tlsSettings.alpn.isEmpty())
            vmessUriRoot["alpn"] = tlsSettings.alpn.join(',');
    }
    return QStringLiteral("vmess://").append(Common::Base64Encode(Common::JsonToString(vmessUriRoot, QJsonDocument::Compact)));
}
