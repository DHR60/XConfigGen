#pragma once

#include "models/xray/Xray.h"

#include <QDir>
#include <QUuid>

namespace XConfigGen
{

namespace Common
{
#define REGEX_IPV4_ADDR \
    R"((?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,2}|1\d\d|2[0-4]\d|25[0-5]))"
#define REGEX_IPV6_ADDR \
    R"(\[\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*\])"
#define REGEX_PORT_NUMBER R"(\b(?:[0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-5][0-5][0-3][0-5])\b)"

std::optional<QString> SafeBase64Decode(QString string);
QString SafeBase64Encode(const QString &string, bool trim);
QString Base64Encode(const QString &string);
std::optional<QString> Base64Decode(const QString &string);
QString JsonToString(const QJsonObject &json, QJsonDocument::JsonFormat format = QJsonDocument::JsonFormat::Indented);
QString JsonToString(const QJsonArray &array, QJsonDocument::JsonFormat format = QJsonDocument::JsonFormat::Indented);
QString VerifyJsonString(const QString &source);
QStringList SplitLines(const QString &str);
const QString GenerateRandomString(int len = 12);
inline QString GenerateUuid()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}
inline QString TruncateString(const QString &str, int limit = -1, const QString &suffix = "...")
{
    QString t = str;
    t.truncate(limit);
    return (limit == -1 || str.length() < limit) ? str : (t + suffix);
}
namespace validation
{
const inline QRegularExpression __regex_ipv4_full("^" REGEX_IPV4_ADDR "$");
const inline QRegularExpression __regex_ipv6_full("^" REGEX_IPV6_ADDR "$");

inline bool IsIPv4Address(const QString &addr)
{
    return __regex_ipv4_full.match(addr).hasMatch();
}

inline bool IsIPv6Address(const QString &addr)
{
    return __regex_ipv6_full.match(addr).hasMatch();
}

inline bool IsValidIPAddress(const QString &addr)
{
    return !addr.isEmpty() && (IsIPv4Address(addr) || IsIPv6Address(addr));
}

inline bool IsValidDNSServer(const QString &addr)
{
    return IsIPv4Address(addr)
           || IsIPv6Address(addr)
           || addr.startsWith(QStringLiteral("https"))
           || addr.startsWith(QStringLiteral("h2c"))
           || addr.startsWith(QStringLiteral("quic"))
           || addr == QStringLiteral("localhost")
           || addr == QStringLiteral("fakedns");
}
} // namespace validation
} // namespace Common

namespace Xray
{
Outbounds4Ray Deserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag = {});
Outbounds4Ray VmessJsonDeserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag = {});
const QString Serialize(const Outbounds4Ray &outbounds, const QString &alias);
const QString VmessJsonSerialize(const Outbounds4Ray &outbounds, const QString &alias);

} // namespace Xray

} // namespace XConfigGen
