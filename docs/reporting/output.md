# 調査報告書一式の利用方法と出力契約

```sh
java -jar target/webauditJ.jar access.log access.log.1.gz --report-dir report-ja --lang ja \
  --report-title "アクセスログ調査" --system-name "対象システム" \
  --investigation-background "調査を開始した背景" \
  --investigation-purpose "疑わしい要求と追加調査事項の整理" --investigator "担当者"
java -jar target/webauditJ.jar access.log --report-dir report-en --lang en
```

出力先は未作成のディレクトリに限る。既存の空ディレクトリ・ファイル・symlinkも置き換えない。`-o`/`--format`との併用は引数エラー。既存の単一HTML/JSON/CSVとwatchは引き続き別モードとして動作する。メタデータは任意入力で、未指定情報はHTMLに未指定と表示する。`--lang`はbundleの説明文に適用するが、JSON/CSVのキー・enum・ルールID・元証跡は変換しない。外部ルールの原文説明や条件は原文を保持する。

| 成果物 | 内容 |
|---|---|
| report.html | 11章、目次、概要、全アクセス統計、カバレッジ、一覧/詳細/戻りリンク、生ログ代表例、事実と推定、推奨対応、印刷CSS |
| report.json | `webaudit/investigation-1`共通モデル。既存解析結果は`analysis`に保持 |
| manifest.json | `webaudit/manifest-1`、build/実効条件/制限/ルールhash/DB来歴/入力hash/完全性/成果物hash |
| log-inventory.csv | 入力ごとの原本ID・サイズ・hash・期間・行数・format・timezone・利用field・診断 |
| analysis-rules.csv | 全既存ルールのengine・種類・条件・必要field・支援状態・優先度 |
| analysis-coverage.csv | 全観点と全ルールの評価、完全性、hit有無、対象/直接検出/関連request・検出・事案 |
| findings.csv | 保持事案全件、件数、成否等。details_jsonに既存事案と追加観測統計 |
| detections.csv | WA署名の各request/rule一致、および保持された集計・独立検出group |
| suspicious-requests.csv | 一意な直接検出観測全件。複数rule/engine一致はID列で関連付け |
| related-requests.csv | 保持された集計条件への関連観測。正常アクセスも含む |
| recommendations.csv | 関連事案/検出、優先度、理由、照合対象、成功/失敗を裏付ける証拠、追加調査/予防策の区別 |
| statistics/*-summary.csv | method/status/class/IP/host/URI/UA/protocol/logtype、利用可能な国/ASN、数値統計 |
| statistics/timeline.csv | UTC・期間に応じた分/時/日等のrequest、不審、4xx、5xx |
| diagnostics/* | 上限付きparse/exclusion診断、execution-log.txt |

manifestは自身のhashを含まない。原本hashはgzipを含む保存状態のファイルbytesのSHA-256で、展開後の内容hashではない。読み取り前後でhashを比較する。サイズ制限・不読・変更時はhash品質と解析完全性を下げる。この比較は外部プロセスによる全ての瞬間的な変更をロック・証明するものではない。

## 数え方

母数はパース成功し、明示dedupで除外されなかった**元ファイル・行の観測**。同文でも別の行/ファイルは別観測とする。ローテーションの重複は`--dedup-files`でファイル単位に扱える。記録だけからネットワーク上の同一HTTP取引を確定するものではない。空行は除外、構文不明はunparsedとして記録する。

Request IDは原本の正規化済みパス由来FILE-IDと元行番号から生成する。アプリケーションのネイティブrequest IDと同一ではない。Findingは既存WA-ID、Detectionはengine/rule/対象group/期間等、CoverageとRecommendationは別IDを使用する。マスクでパスが同じ表示になってもFILE-IDと元行番号は保持する。

不審requestは少なくとも1件の直接検出に属する観測を1回数える。検出数は同じ観測に一致した各rule、または各保持集計groupを数える。事案数は既存Correlatorの保持事案数。Hub/Auraは独立集計であり、無条件にWA事案へ統合しない。WAの集計・AuraAnalysisのgroup内観測は関連証跡とし、その全てを直接攻撃とみなさない。単一点のサイズ異常と実際に成立したHub/Aura署名membershipは直接関連として扱う。Hubはdistinct適用後のaccepted bucketと実際のemitだけを解決する。

観点・ルール・engineの件数は重なるため、一意requestの算出に合計してはいけない。各観点の直接/関連requestも観点内で一意とする。Geo類似性は主体同一性・悪性の証明ではなく、request membershipが確定しない値は空欄/nullとする。署名候補数と実際に成立したgroup数も別の列である。

割合はパース済み非dedup観測が分母。全体母数0ではnull、不審0/既知の正母数では0。欠損fieldはunknown、既知のサイズ0は0を維持する。処理時間は単位の明確なnginx JSONのrequest_time（秒）かcustom regexのduration_secondsのみ使用し、他の数値から推測しない。数値合計は浮動小数点の丸めを伴い、overflow時はnullとqualityを出す。

`exact`は記録・条件・設定範囲での件数、`lower_bound`は上限や入力不完全性による下限、`unavailable`は評価不能。解析完全性、証跡完全性、各fieldの品質を別に保持する。未対応と検出なし、部分評価と検出ありは独立して表示する。検出なしは今回の範囲・条件での結果で、安全や侵入不存在の証明ではない。

## 上限と機密性

既定の`--max-spool-bytes`と`--max-report-bytes`は各1 GiB。前者は全観測snapshotのprivate JSONL一時ファイル、後者は成果物合計。既存max-line/file/keys/findings/evidenceも適用する。全件CSVはメモリに全件を載せず、一時ファイルを逐次再生して出す。入力を再走査して元証跡を再生成しない。spool上限では解析と全アクセス統計を継続し、全件証跡と不審集計を下限扱いにする。

HTMLは事案/独立検出各100件、coverage/rule各1000件、ランキング20–30行、timeline120区間などに制限する。別紙は保持された全件を扱い、全体上限・一時ファイル上限・事案/keys上限による不完全性は隠さない。URI例は8件、各1024文字、methodは64種類、case timelineは64区間。その他bucket、切詰め、ユニーク数の下限を表示する。

正常終了時にprivate spoolとINCOMPLETE markerを削除する。成果物容量超過等の失敗ではmarkerを残し、完成した報告書として扱わせない。異常終了後の出力も機密資料として扱う。サンプル入力は合成データである。

標準HTML escape、CSV formula guard、JSON serializerを使用し、制御文字/Bidi制御は可視化する。外部script/CDN/imageを使用しない。既定で一般的な秘密query/header/JSON値をマスクする。`--include-sensitive-evidence`は明示的なマスク解除で、制御文字の可視化は解除しない。任意形式の全秘密や個人情報の検出・匿名化は保証せず、IP・調査担当者も匿名化しない。共有前に提出範囲を確認する。元ログは変更しない。

## 判断の意味と残る限界

既存severityはルール優先度として引き継ぎ、影響が確認されたという新しい意味へ変換しない。検出確度は独立した評価根拠が未整備のためunknown。既存outcome/confidenceはその意味を維持し、scoreやconfidenceを校正確率へ変換しない。HTTP200、403、404だけで侵入成功・失敗を確定しない。事実、ruleによる推定、未確認事項、正常アクセスの可能性、脆弱性が存在する場合の影響を区別する。

本文専用攻撃・IP reputation等は未対応としてcoverageに残す。現在の解析で利用できるerror/auth indicatorは対象に含めるが、入力を渡すだけで任意のDB/OS/application監査を解釈できるものではない。GeoDBなしでは地域/ASNを補完せず、DB精度だけで悪性と判断しない。順序依存のHub検出、既存の固定時間窓、共通/部分ルール、入力項目不足、母数不足などを個別に開示する。

追加調査案内は既存の攻撃別Investigationを再利用し、対象時刻/IP/host/URIを付ける。任意のシステム構成、脆弱性、レスポンス本文、侵入、損害の事実は生成しない。独立検出の成否・confidenceは未評価のまま保持する。

## サンプルと検証

[日本語](../../examples/investigation-ja/report.html) / [English](../../examples/investigation-en/report.html)。各ディレクトリにJSON/CSV/manifestも含む。入力は`examples/sample.log`で、絶対原本パスとJAR fingerprintは生成環境の値である。再生成する際は未作成の別出力先を指定する。

テスト対応表と残存事項は[traceability.md](traceability.md)、測定手順・生値は[performance.md](performance.md)を参照。

統計別紙の`count_quality`は全観測件数、`suspicious_count_quality`は不審件数の品質を表す。spool上限等で後者だけが下限になる場合もCSV単体で開示する。数値統計のcount/missing/invalidは排他的に計数し、不正値を欠損数へ二重計上しない。

Java版のmanifest.buildはJVM/OS/archと配布JAR自身のSHA-256を記録する。IDEやclasses directoryから実行した場合はartifact_hash_scope=classes_directory_unhashed、hash=nullとして非取得を明示する。JARの識別は生成時のbytesであり署名検証ではない。HTMLの入力一覧も1000件まで。
