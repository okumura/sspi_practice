# Windows SSPI/Schannel サンプルコード

このリポジトリには、Windows Security Support Provider Interface (SSPI) および Schannel (TLS/SSLプロバイダ) を使用するためのC言語のサンプルコードが含まれています。これらのサンプルは、Windows環境でのセキュリティ関連のプログラミングタスクを理解するのに役立ちます。

## 含まれるファイル

1.  **`enum_sec_pkgs.c`**
  *   システムで利用可能なセキュリティパッケージを列挙して表示します。
  *   `EnumerateSecurityPackages` 関数の使用方法を示します。

2.  **`schannel_init.c`**
  *   Schannel を使用してクライアント側のTLSハンドシェイクを開始する方法を示します。
  *   生成された ClientHello メッセージを解析し、その内容（バージョン、暗号スイート、拡張機能など）を表示する `print_client_hello` 関数が含まれています。
  *   `AcquireCredentialsHandle` および `InitializeSecurityContext` 関数の基本的な使用方法を示します。

## ビルドと実行

これらのサンプルコードをビルドするには、Cコンパイラ（MinGWやMicrosoft Visual C++など）が必要です。コンパイル時には、`secur32.lib` ライブラリをリンクする必要があります。

**例 (MinGW GCCを使用する場合):**

```bash
gcc enum_sec_pkgs.c -o enum_sec_pkgs.exe -lsecur32
gcc schannel_init.c -o schannel_init.exe -lsecur32
```

**実行:**

```bash
./enum_sec_pkgs.exe
./schannel_init.exe
```

`schannel_init.exe` はデフォルトで "localhost" に対して ClientHello を生成しようとします。

## 注意事項

* これらのコードは Windows 専用です。
* Schannel の機能は、実行している Windows のバージョンによって異なる場合があります。
* エラーハンドリングは最小限です。実際のアプリケーションでは、より堅牢なエラーチェックが必要です。
