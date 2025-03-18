# XConfigGen

一个使用 QSerializer 库为 Xray/V2ray 生成 JSON 配置的工具。它基于反射机制，能够自动序列化和反序列化数据。

## 请注意，目前仅支持将源文件添加到项目，尚不支持以库的形式引入。

会报错 `无法解析的外部符号 "public: static struct QMetaObject const`

~~求个大佬帮我解决下？~~

需要引入以下文件：

头文件：
- 3rd/QSerializer/src/qserializer.h
- src/XConfigGen.h
- src/models/xray/Xray.h

源文件：
- src/XConfigGen.cpp

## 如何使用

查看[示例](/examples)

## 特别感谢

顺序不分先后：
- [Xray-core](https://github.com/xtls/xray-core)
- [2dust/v2rayN](https://github.com/2dust/v2rayN)
- [smurfomen/QSerializer](https://github.com/smurfomen/QSerializer)

## 目标

- [x] Xray-core
- [ ] Sing-box
- [ ] 修复以库的方式使用时，报错`无法解析的外部符号 "public: static struct QMetaObject const`
