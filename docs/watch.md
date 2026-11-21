# リアルタイム監視とHook

## 起動・入力

```sh
java -jar target/webauditJ.jar watch access.log
java -jar target/webauditJ.jar watch access.log another_access.log --from beginning
java -jar target/webauditJ.jar watch /var/log/nginx/ --include '*access*.log' --exclude 'private*'
java -jar target/webauditJ.jar watch access.log --format jsonl
```

監視はフォアグラウンドで動作します。`Ctrl+C` で読み取りを止め、チェックポイントを保存し、
Hookと子孫プロセスを終了してから戻ります。サービス登録・権限昇格は行いません。
従来の `java -jar target/webauditJ.jar access.log`、HTML/JSON/CSVレポートは変更していません。

Apache/Nginx Common/Combined、既存パーサーが認識するJSONなどの、時刻とタイムゾーンが
確定したアクセスログを処理します。errorログ・時刻不明ログは検知へ渡しません。
不正UTF-8や不正なログは診断を出してスキップします。watchではカスタムlog-regexは未対応です。

ディレクトリ探索は直下だけです。既定の候補名は大文字小文字を区別せず `access`、`access.log`、
`*_access.log`、`*-access.log`、`*.access.log` です。`error.log`、番号付きローテート済みログ、
無関係なファイルは自動選択しません。`--include` はファイル名のglobで候補条件を置き換え、
`--exclude` をその後適用します。候補でも最終的にパーサーがアクセスログと認識した行だけを
解析します。gzip・シンボリックリンク・非通常ファイルは入力として認めません。
macOSのOS標準別名 `/var`・`/tmp`・`/etc` が対応する `/private/` 配下を指す場合は受け入れます。
利用者が作成したリンクは、入力・状態保存先とも引き続き拒否します。
明示したファイルが一時的に存在しない場合は、作成を待ちます。

## 開始位置・ローテーション

初回はEOFから開始します。既存末尾が部分行なら、その行の残りも次の改行まで捨てます。
`--from beginning` は先頭から読み、その後は追記監視します。保存済みのファイルID、
オフセット、部分行がある場合、`--from` より復元を優先します。

```sh
java -jar target/webauditJ.jar watch access.log --reset-state --from beginning
java -jar target/webauditJ.jar watch access.log --no-state --from beginning
```

250msのポーリングでファイル状態とディレクトリを確認します。
`--poll-interval 1s` のように変更できます（10ms〜1分）。ファイルIDはLinuxのdev/inode、
Windowsのvolume/file indexを使い、消費済み末尾128バイトのSHA-256アンカーも照合します。
rename後も開いている旧ハンドルを読み、新ファイルは先頭から読みます。旧ファイルに未読の
バックログがあれば新ファイルの読み取りを待たせます。旧ファイルはEOF後、切り離されて
2秒以上経過すると閉じます。これ以降の旧ファイルへの追記は対象外です。

サイズ縮小やアンカー不一致でcopytruncate/書き換えを検出し、警告して先頭へ戻します。
コピーと切り詰めの間に失われるログは復元できません。ポーリング間で作成・削除されたファイル、
同じアンカーを再現するtruncate-and-regrow、ファイルID再利用も完全には識別できません。
改行前の部分行は保持し、次の追記と結合します。上限超過行は次の改行まで捨てます。

## 検知・インシデント・時刻

既存の Java `LogParser`、`Signatures`、`Normalizer`、`Behavior`、`Correlator` と成否推定を使います。
一行の検知を、同じIP・host・User-Agent・技法family・5分区間でインシデントへ集約します。
これは攻撃者の同一性を証明するものではありません。後続ログで重要度や成否が変わると
同じIDのrevisionが増えます。HTTPステータス単独で攻撃成功を断定しません。
watchでは機密グループ値をハッシュ化して保持するため、watchのインシデントIDとバッチのIDは一致しない場合があります。

記録時刻と受信時刻を区別します。`--allowed-lateness 30s` が既定で、最大の記録時刻より
許容時間を超えて古いイベントを警告して捨てます。保持内は安定した記録時刻順に再評価します。
受信時刻より5分以上未来のログはwatermark汚染を防ぐため捨てます。
区間末尾＋遅延許容時間をwatermarkが超えるか、更新が5分＋遅延許容時間停止するとcloseします。
確定済み区間へ届いたログは再開せず捨てます。closeは攻撃終息の証明ではありません。

保持は既定15分・8192イベント・2000インシデントです。`--retention`（5分＋遅延許容以上、
最大24時間）、`--max-events`（最大100000）で変更できます。期限切れ状態と通知履歴を整理し、
上限到達は警告します。保持上限で欠けた情報を含む検知結果は不完全です。
`--max-files` は既定64、`--max-line-bytes` は既定65536です。1ファイル1回の読み取りは
1MiBまでで、キャンセルと他ファイルの処理を妨げないようにします。

バッチとwatchは同じネイティブ検知ルールを使いますが、全履歴と有界保持、遅延廃棄、
時刻順再評価、チェックポイント開始位置によって結果に差が出ます。オンラインサイズ基準や
leaky bucketは入力順に敏感です。バッチのAura/Hub由来の互換性確認用 `upstream_alerts` /
`aura_analysis` 等の別レポート集合はwatchイベントには出しません。
watchは有界イベントを再評価する方式のため、大きな保持数・高い追記頻度ではCPU負荷が増えます。

## JSONLスキーマ1

機械可読な定義は[watch-event.schema.json](watch-event.schema.json)です。

`--format jsonl` のstdoutは1行1イベントのJSONのみです。起動案内、警告、Hook結果はstderrです。
text表示もcreated/updated/closedを区別し、大量の生ログを表示しません。

| フィールド | 意味 |
|---|---|
| schema_version | 整数1。追加フィールドは将来増える可能性あり |
| event_type | incident_created / incident_updated / incident_closed |
| event_id | incident_id・revision・イベント種別から作る安定ID |
| sequence | 対象セット内の出力連番。保存・復元され、明示リセットで初期化 |
| incident_id, revision | 事案IDと単調増加する版番号 |
| created_at, updated_at | WebAuditが作成・更新したUTC受信側時刻 |
| first_event_at, last_event_at | 対象ログの最初・最後の記録時刻 |
| severity, category | low/medium/high/critical とネイティブカテゴリ（複数はカンマ区切り） |
| outcome, confidence | 既存成否推定と0〜1の確信度。侵害の確定を保証しない |
| source_ips | 記録された送信元IPの配列（現在の集約は単一IP） |
| evidence | 原本参照の配列。各要素はfile・lineのみ。元の行番号が不明な末尾開始ではline=0 |
| rule_ids, count | ルールID一覧と集約件数 |
| geoip | 任意。既存GeoIPInfo形式のcountry_code、asn、status等 |

rawログ・URL・クエリ・User-Agent・Referer・Cookie・Authorizationは出力しません。
証拠の内容はfile/lineから原本を確認してください。イベントはincident ID順に評価し、
末尾開始では行番号を得るために全ファイルを数え直しません。line=0は不明を意味します。
ローテーション前の証拠のfileは元の監視パスを示すため、記録時刻・IPとローテート済み原本も照合してください。
出力順はsequenceで確認できます。受信の分割や再起動位置によって中間revision数は変わり得ます。

## チェックポイント

Linuxは `$XDG_STATE_HOME/webauditJ/watch/`、未設定なら `~/.local/state/webauditJ/watch/`。
Windowsは同じ絶対XDG_STATE_HOMEを優先し、未設定なら `%LOCALAPPDATA%/webauditJ/watch/`。
相対パスの状態ルートは誤配置を防ぐためエラーにします。
正規化・ソートした入力パス集合のハッシュごとにJSONスナップショットとOS排他ロックを作ります。
対象が重なる別のパス集合は独立セッションなので重複監視できます。同じ集合の同時起動は拒否します。

1秒ごとと正常終了時に、ファイルID・オフセット・部分行・アンカー、縮約イベント、
インシデント・revision・sequence・確定watermark・通知済みrevisionを保存します。
既存履歴のURL/ヘッダーは保存せず、必要な分類はルールID、グループキーはハッシュにします。
ただし部分行には原文が必要です。保存先は自分だけが読める場所にしてください。
Unixは0600/0700を使い、Windowsは保存先のユーザーACLを継承します。

状態は32MiBを上限にし、SHA-256・スキーマ・ルール版・設定・対象パス・コレクションを検査します。
不完全・破損・不互換なら停止して `--reset-state` を案内します。部分復元はしません。
SHA-256は事故による破損検出で、同じOSユーザーによる改ざんを認証するものではありません。
同じディレクトリに一時保存し、sync後に原子的に置換します。失敗した保存で旧状態を壊しません。
24時間より古い書き込み一時ファイルを整理します。別の入力セットのチェックポイントは自動削除せず、
不要なら監視停止中に対象ファイルを管理してください。空のlockファイルはOSロック解除後も残ります。

強制終了では直近1秒程度が再処理され得ます。出力/外部Hookと状態保存は単一トランザクション
ではないため、完全なexactly-onceは保証しません。アンカー不一致や復元不能な旧ファイルは警告します。

## Hook

```sh
java -jar target/webauditJ.jar watch access.log --on-detect ./examples/notify.sh
java -jar target/webauditJ.jar watch access.log --on-detect ./examples/notify.sh --on-detect-event all
java -jar target/webauditJ.jar watch access.log --on-detect './path with spaces/notifier' --on-detect-arg=literal
```

```powershell
java -jar target/webauditJ.jar watch .\access.log --on-detect powershell.exe `
  --on-detect-arg=-NoProfile --on-detect-arg=-File `
  --on-detect-arg=examples/notify.ps1
```

`--on-detect` は実行ファイルそのものです。コマンドライン全体を渡したりシェルとして解釈したり
しません。`--on-detect-arg` は直前のHookへ文字列をそのまま追加します。複数Hookは
`--on-detect` を繰り返します（最大16、各64引数）。Linuxの.shは実行権限とshebangが必要です。
Windowsの.ps1は例のようにPowerShellを明示します。ログ値のコマンド・引数への展開機能はありません。
PowerShellの実行ポリシーで許可されるスクリプトを使用してください。WebAuditは実行ポリシーを変更しません。

| オプション | 既定 |
|---|---|
| --on-detect-severity | high（low/medium/high/criticalの最低重要度） |
| --on-detect-event | created（created/updated/all） |
| --hook-timeout | 10s（1ms〜1h） |
| --hook-concurrency | 1（最大32） |
| --hook-queue-size | 128（最大4096、FIFO） |

createdは作成のみ、updatedは更新のみ、allは両方です。更新通知は重要度の上昇または成否の変化
だけで、件数だけの増加は通知しません。closedは通知しません。最低重要度は更新時にも適用します。
キューが満杯なら非同期通知を捨て、欠落件数を警告します。重要度別の優先配送は行いません。
失敗時の自動リトライはなく、監視は継続します。診断は同じメッセージを5秒に1回、全体でも
5秒あたり10件に制限し、抑制件数も報告します。

標準入力は上記IncidentEventと同じJSONに `hook_id` と `notification_id` を追加した1行です。
notification_idは事案ID・revision・Hook設定から安定生成します。rawログは渡さず、JSONは64KiBまで、
子のstdout/stderrは並行して読み捨て、保持・再表示しません。
通知済みrevisionはキュー受付時に記録します。停止でキューを破棄するため配送はbest effortです。
実行済み副作用の再発生・未実行の通知欠落の両方がクラッシュ境界で起こり得ます。
重要な受信側はnotification_idを使って冪等に処理してください。

HookはWebAuditと同じOSユーザー・作業ディレクトリ・継承環境で動きます。
環境にある秘密情報も継承するため、信頼する実行ファイルを指定してください。
Hook専用の小さなJava補助プロセスを起動し、Unixは新しいsession/process group、WindowsはJob Objectへ収容します。
収容成功後にだけ実行ファイル・引数・イベントを渡し、timeout/終了時に子孫も終了します。
補助JVMの起動時間もHookのタイムアウトに含みます。Windowsの.cmd/.batは直接指定できません。
JDKのForeign Function & Memory APIを使い、実行可能JARのManifestでnative accessを有効化しています。
クラスパスから起動する開発時は `--enable-native-access=ALL-UNNAMED` を付けてください。
プロセス封じ込めに失敗した場合、Hookの起動を失敗させて警告します。任意の悪意ある実行ファイルに
対するサンドボックスではありません。明示的にセッションを離脱するUnix子孫までの隔離は保証しません。

## GeoIP

既存のXDGデータディレクトリの管理DBを自動検出し、実行ファイルのgeoipディレクトリへの
従来の探索と `--geoip-country` / `--geoip-asn` も使えます。ローカルMMDBと既存LRUキャッシュだけを
使用し、監視中にダウンロードや外部API照会はしません。DB未導入・自動探索DBの破損時も監視を続けます。
明示した壊れたDBは入力設定エラーです。開始時のDBを終了まで保持し、DB更新の反映にはwatchを再起動します。
国・ASNは文脈情報のみで、攻撃判定や成否の確信度を変えません。

## Java版の互換性

移植元はGo版v2.0.0（`96e3c8a3148d1684d60abac22d3aa2939354e891`）です。JSONL schema 1と検知ルールを維持します。チェックポイントの内部形式・保存先はJava版専用で、Go版との相互復元はできません。Hook IDは言語ごとの設定シリアライズに由来するため、notification_idも言語間で一致する保証はありません。通常の監視はオフラインです。Hookで通信する実行ファイルを明示した場合は、その実行ファイルの動作に従います。

Hookの補助JVMを通知ごとに起動するため、Go版と起動コストが異なります。通常の監視・バッチ解析で追加の外部ランタイムは不要です。通知サンプルのnotify.shだけPython 3を使います。
