#pragma once

#include "models/xray/Xray.h"

#include <QDir>
#include <QUuid>

namespace XConfigGen
{

namespace Common
{
std::optional<QString> SafeBase64Decode(QString string);
QString SafeBase64Encode(const QString &string, bool trim);
QString Base64Encode(const QString &string);
std::optional<QString> Base64Decode(const QString &string);
inline QString GenerateUuid()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}
} // namespace Common

namespace Xray
{
Outbounds4Ray Deserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag = {});
Outbounds4Ray VmessJsonDeserialize(const QString &uri, QString &alias, QString &errMessage, const QString &tag = {});
const QString Serialize(const Outbounds4Ray &outbounds, const QString &alias);
const QString VmessJsonSerialize(const Outbounds4Ray &outbounds, const QString &alias);

} // namespace Xray

} // namespace XConfigGen
