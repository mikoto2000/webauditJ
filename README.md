# WebAuditJ

最新リリース: [v2.0.2](https://github.com/mikoto2000/webauditJ/releases/tag/v2.0.2)。変更点は [リリースノート](docs/releases/v2.0.2.md)を参照してください。

HTTP サーバーのログをオフラインで調査する Java 版 WebAudit。Go 版の `95148ba4e22d9001d34fbb0e4d59f072efd3e95c` を基準に、独自検知、Hub/Aura 互換検知、事案の関連付け、GeoIP/ASN 補足情報と DB 管理を移植しています。

Go 版 main `a26ee0ff1e1bb3d5c88979cf6c0854898f3e5459` までの追加機能にも対応しています（参照値は [baseline.json](docs/reference/baseline.json)）。攻撃別の追加調査ガイド、HTML の日本語表示と言語選択、集約上限・GeoIP 警告・端末表示・不完全なレポートの削除に関する修正を含みます。

Go 版 **v2.0.0** のリアルタイム監視・JSONL事案イベント・チェックポイント復元・外部コマンドHook・ローカルGeoIP補足に対応しました。詳細は [監視・Hookガイド](docs/watch.md)、[移植検証記録](docs/watch-validation.md)を参照してください。

```sh
java -jar target/webauditJ.jar watch access.log
java -jar target/webauditJ.jar watch access.log --from beginning --format jsonl
java -jar target/webauditJ.jar watch access.log --on-detect ./examples/notify.sh
```

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

初回ビルドは Maven と依存のダウンロードに通信します。キャッシュは `.build/` に置きます。生成した JAR の通常解析は通信しません。レポートの出力先には新しいファイルを指定してください。既存ファイルは上書きしません。`-o ./output/nested/index.html` のように指定すると、保存時に不足する親フォルダーを再帰的に作成します。Unix の新規フォルダーは所有者のみアクセス可能です。親パスがファイルの場合や作成権限がない場合は終了コード 2 になります。保存に失敗しても作成した親フォルダーは残ります。

```sh
java -jar target/webauditJ.jar access.log rotated.log.gz logs/ --format json -o report.json
java -jar target/webauditJ.jar access.log --format csv -o report.csv
java -jar target/webauditJ.jar --help
java -jar target/webauditJ.jar --version
```

ディレクトリは再帰的にファイル名順で読み、gzip は内容で判別します。同じ観測を繰り返し入力した場合も集計します。`--dedup-files` を指定したときだけ、ファイル全体の SHA-256 で重複を除きます。出力先を省略すると端末向け要約を、`--format json|csv|html` を指定するとその形式を標準出力へ出します。`-o` の既定形式は HTML です。

Apache/Nginx のアクセス・エラーログ、JSON、syslog/journald、Nginx Proxy Manager と明示正規表現に対応します。独自形式の `--log-regex` は RE2 構文で、`(?P<ip>...)`、`(?P<time>...)`、`(?P<target>...)` が必須です。タイムゾーンのないエラーログには必要に応じて `--error-timezone Asia/Tokyo` を指定します。

LB / CDN / リバースプロキシ配下では、Apache / Nginx 側で信頼する中継元から元 IP を復元し、解析対象の IP 欄に記録してください。[LB 配下での設定ガイド](docs/load-balancer.md)に、Apache / Nginx の XFF・PROXY protocol 設定例、動作確認手順、IP 集計・GeoIP への影響と過去ログの限界をまとめています。

## HTML の言語と追加調査ガイド

HTML は既定で日本語です。英語で出力する場合は `--lang en` を指定します。

```sh
java -jar target/webauditJ.jar access.log -o report-ja.html
java -jar target/webauditJ.jar access.log --lang en -o report-en.html
java -jar target/webauditJ.jar access.log --format html --lang ja
```

指定値は小文字の `ja` / `en` だけです。空・未対応値は入力解析や出力ファイル作成前に終了コード 2 で拒否します。`--lang` は HTML にだけ適用し、端末要約・ヘルプ・JSON・CSV の内容や判定コードは変更しません。ログ、URL、IP、ホスト名、User-Agent、ルール ID、DB の国名・組織名、構造化レポートとライセンス本文は原文を保持します。OS・外部ライブラリの診断も詳細を原文で表示します。

事案の詳細には、SQL インジェクション、コマンド実行、機密ファイル、XSS、認証、大量アクセスなど、検出の種類に応じた「不明な理由」「確認する場所」「何が見つかれば判断できるか」を表示します。複数の種類を検出した場合は各種類を案内します。成功・失敗の疑いがある場合やタイムゾーンが不明の場合も案内を保持します。端末の上位 5 事案、JSON の `outcome.investigation`、CSV の `details_json` にも含めます。Hub/Aura の独立した検出には追加しません。

HTML の「独立したHub・Auraの検出」は、一覧表から各詳細へ移動できます。詳細に検出元の生ログを最大8件、1件あたり4096バイトまで表示します。Aura の集計検出は、その集計対象に属するログの例です。生ログは解析中に保持し、合計保持量は独自事案の証拠とは別枠で `--max-evidence-bytes` を上限とします。省略時は警告を表示します。生ログの保持はHTML出力時のみ行います。

案内は証拠を探す目安です。時刻・タイムゾーン・対象ホスト・URL、可能ならリクエスト ID で当時の記録と照合してください。痕跡がないだけでは失敗と判断できず、失敗の証拠は確認した要求の範囲に限られます。現在の環境での再現だけでは当時の成否を確定できません。追加証拠による自動再判定は行いません。

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


## 調査報告書一式

```sh
java -jar target/webauditJ.jar access.log --report-dir report --lang ja --system-name "対象システム" --investigator "担当者"
```

新規ディレクトリを排他的に作成するバッチ専用モードです。11章構成の日英HTML、原本来歴・入力別診断・manifest・全調査観点カバレッジ・全件証跡・全アクセス統計・事案別調査案内を生成します。[移植設計](docs/reporting/design.md)と[要求対応表](docs/reporting/traceability.md)を参照してください。

任意metadataは`--report-title`、`--system-name`、`--investigation-background`、`--investigation-purpose`、`--investigator`。`--lang ja|en`を選択できます。`-o`/`--format`とは排他です。既存の単一ファイル出力は維持します。`--max-spool-bytes`、`--max-report-bytes`は各既定1 GiBです。原本SHA-256はgzipを含む保存bytesの前後照合で、元ログは変更しません。生成失敗時のINCOMPLETE marker付き出力は完成報告書として扱わないでください。現段階の証跡には元ログと同等の機密性があります。


`analysis-rules.csv`は全既存の独自署名・行動/統計・Hub・Aura・地理相関の条件と必要項目を出力します。`analysis-coverage.csv`と共通JSONは、検出有無と評価の完全性を別に保持し、未対応/未実施/評価不能/部分評価/検出あり/検出なしを区別します。本文専用攻撃とIP reputationは未対応として残します。統計母数不足やログ項目欠損を無検出と混同しません。保持された検出への直接/関連requestを一意に関連付けます。Geo context等、確定できない件数は空欄/nullです。


`suspicious-requests.csv`は直接検出された元file/line観測を一度ずつ出力します。`related-requests.csv`は集計条件に関連する正常アクセスも含み、不審の断定ではありません。両者の重なりはdirect/related ID列で開示します。`detections.csv`は各WA署名一致と各保持group、`findings.csv`は保持事案全件と上限付き観測統計です。事案の成否を個々のrequestへ自動転記しません。Request IDはfile ID+lineからの生成IDで、アプリのnative IDと区別します。

spool上限に達しても既存解析を継続し、全件証跡と該当集計を下限扱いにします。終了時に成立する統計的検出も、元ログの再走査をせずsnapshotに関連付けます。正常終了時・出力エラー時にはprivate spoolを削除します。強制終了時はINCOMPLETE付き出力を機密資料として扱ってください。異なる元file/lineに同じ内容があれば別観測です。


`statistics/`に全観測と不審観測のmethod/status/class/IP/host/URI/UA/protocol/logtype別集計、レスポンスサイズと取得可能な処理時間、adaptive UTC時系列を出力します。GeoDBがある場合は国/ASN・組織名・ユニークIP・lookup状況も含みます。処理時間は単位が明確なnginx JSONのrequest_time（秒）またはcustom regexのduration_secondsだけを採用し、欠損・不正・0を別扱いにします。数値overflowはnull/qualityで開示します。各次元はmaxKeys・ラベル長、時系列はbin上限で制限し、other/切詰め/下限を明示します。

分母はパース済み・非dedupの元file/line観測で、ネットワーク上の一意HTTP取引数とは限りません。観点・rule・engineの件数は重複するので単純加算しません。spool上限後も全アクセス統計は既存streamから継続し、不審件数の品質はsuspicious_count_qualityで独立表示します。ログがない時間帯を欠損や停止と断定しません。


### 11章の報告書と機密値

`report.html`は外部通信なしで表示・印刷できます。目次、事案と独立したHub/Auraの一覧、詳細・ルール・coverageへのリンク、一覧へ戻るリンク、生ログ代表例、値付きグラフを備えます。HTMLは事案/独立検出各100件、rule/coverage/入力各1000件、ランキング20–30行、全体timeline120区間に制限し、別紙で全保持データを確認できます。

観測事実・ruleによる推定・未確認事項・正常アクセスの可能性・脆弱性が存在する場合の影響を分けます。severityは既存rule優先度を保持し、検出確度が別に評価されていない場合はunknownです。既存のscore/outcome/confidenceを校正確率へ変換しません。追加調査と条件付き予防策を区別し、既存の攻撃別確認案内を再利用します。

既定では一般的なquery秘密キー、Authorization、Cookie等を解析後の公開モデルとCSVでマスクします。元のfile IDとlineから先に参照を作るため、マスク後にファイル名が同じ表示になっても原本を区別できます。`--include-sensitive-evidence`で明示解除できますが、control/Bidi制御文字の可視化は解除しません。全秘密・個人情報の完全匿名化は保証せず、IPや調査担当者も匿名化しません。共有前に内容を確認し、原本と同等のアクセス制御で保管してください。元ログは変更しません。

出力一覧・数え方・制限は[利用方法と出力契約](docs/reporting/output.md)、実測結果は[性能と資源使用量](docs/reporting/performance.md)を参照してください。[日本語サンプル](examples/investigation-ja/report.html)と[English sample](examples/investigation-en/report.html)には同じ入力から生成したJSON/CSV/manifestも付属します。

`--verbose` は stderr に入力ファイルのプログレスバーと読み取り行数を表示します。単一の大きなファイルでも行数は約100ms間隔で更新します。バーは列挙したファイルの処理済み数（重複除外・読み取り失敗を含む）で、解析やレポート生成全体の成功率ではありません。gzip、ディレクトリ、`--report-dir` にも対応します。完了時は改行し、通常レポートのファイル別診断は従来どおり表示します。stdout のレポート形式は変わりません。Go 版 [PR #39](https://github.com/mikoto2000/webaudit/pull/39) の表示仕様を移植しています。
