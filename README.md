# WebAuditJ

HTTP サーバーのログをオフラインで調査する Java 版 WebAudit。Go 版の `95148ba4e22d9001d34fbb0e4d59f072efd3e95c` を基準に、独自検知、Hub/Aura 互換検知、事案の関連付け、GeoIP/ASN 補足情報と DB 管理を移植しています。

Java **25 以上**が必要です。配布形式は依存ライブラリ・ルール・HTML テンプレートを含む実行可能 JAR です。jpackage と GraalVM Native Image は後続工程です。

## ビルドと実行

Windows (PowerShell):

```powershell
.\mvnw.cmd -s .mvn/settings.xml verify
java -jar target/webauditJ.jar examples/sample.log
java -jar target/webauditJ.jar examples/sample.log -o report.html
```

Linux/macOS:

```sh
./mvnw -s .mvn/settings.xml verify
java -jar target/webauditJ.jar examples/sample.log -o report.html
```

初回ビルドは Maven と依存のダウンロードに通信します。キャッシュは `.build/` に置きます。生成した JAR の通常解析は通信しません。レポートの出力先には新しいファイルを指定してください。既存ファイルは上書きしません。

```sh
java -jar target/webauditJ.jar access.log rotated.log.gz logs/ --format json -o report.json
java -jar target/webauditJ.jar access.log --format csv -o report.csv
java -jar target/webauditJ.jar --help
java -jar target/webauditJ.jar --version
```

ディレクトリは再帰的にファイル名順で読み、gzip は内容で判別します。同じ観測を繰り返し入力した場合も集計します。`--dedup-files` を指定したときだけ、ファイル全体の SHA-256 で重複を除きます。出力先を省略すると端末向け要約を、`--format json|csv|html` を指定するとその形式を標準出力へ出します。`-o` の既定形式は HTML です。

Apache/Nginx のアクセス・エラーログ、JSON、syslog/journald、Nginx Proxy Manager と明示正規表現に対応します。独自形式の `--log-regex` は RE2 構文で、`(?P<ip>...)`、`(?P<time>...)`、`(?P<target>...)` が必須です。タイムゾーンのないエラーログには必要に応じて `--error-timezone Asia/Tokyo` を指定します。

## GeoIP / ASN

```sh
java -jar target/webauditJ.jar geoip download
java -jar target/webauditJ.jar geoip status
java -jar target/webauditJ.jar geoip update
java -jar target/webauditJ.jar geoip rollback
```

`download` は DB-IP Lite の Country/ASN DB を導入し、導入済みなら通信しません。`update` は配布元へ更新を確認します。`status` と `rollback` はオフラインで動作します。検証済みの現世代と前世代を保持し、失敗した取得で現世代を置き換えません。DB 自体は JAR に同梱しません。

保存先は次の優先順位です。Go 版の `webaudit/geoip` から独立しています。

1. 絶対パスの `XDG_DATA_HOME` 配下の `webauditJ/geoip`
2. Windows: `LOCALAPPDATA/webauditJ/geoip`
3. Linux/macOS: `HOME/.local/share/webauditJ/geoip`

`--geoip-country /path/country.mmdb`、`--geoip-asn /path/asn.mmdb` で各 DB を明示できます。明示指定、管理 DB、JAR 隣の `geoip/` の順に探索します。最後の探索は管理 DB 未導入時だけです。破損した管理 DB は警告して解析を続け、明示 DB の不存在・破損は引数エラーになります。

Windows はファイルロックを残さないメモリ読み込み方式で、DB サイズ分の Java ヒープを使います。Linux/macOS はメモリマップ方式です。GeoIP は補足情報であり、攻撃スコア・重要度・成否の判定には影響しません。位置情報は IP 登録・推定情報です。[IP Geolocation by DB-IP](https://db-ip.com)、CC BY 4.0。

## 上限と終了コード

| オプション | 既定値 | 意味 |
|---|---:|---|
| `--max-line-bytes` | 65,536 | 1 行のバイト数 |
| `--max-file-bytes` | 8,589,934,592 | 1 ファイルの展開後バイト数 |
| `--max-keys` | 4,096 | 追跡キー、GeoIP peer/cache の上限 |
| `--max-findings` | 2,000 | 所見数の上限 |
| `--max-evidence-bytes` | 33,554,432 | 証拠の合計バイト数 |

上限到達や入力エラーによる部分解析はレポートに明示します。終了コードは `0`: 完了、`1`: 部分解析・入出力/管理処理失敗、`2`: 引数・明示 DB・出力先の問題です。`--verbose` はファイル別の解析状況を標準エラーへ出します。Go 版の `-format` 等の単一ハイフン表記も受け付けます。

リクエスト本文・応答本文や認証結果はログから確定できません。転送ヘッダーは信頼せず、記録された接続元を解析します。レポートの根拠と部分解析の警告を併せて確認してください。

## 開発資料

- [移植設計](docs/porting-design.md)
- [検証結果と測定条件](docs/validation.md)
- [開発・検証手順](DEVELOPMENT.md)
- [第三者ライセンスと出典](THIRD_PARTY_NOTICES.md)

本体は MIT ライセンスです。ルール、ライブラリ、テストデータの個別条件は第三者ライセンスを参照してください。
