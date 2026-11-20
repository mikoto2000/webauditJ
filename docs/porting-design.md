# WebAuditJ 移植設計

WebAudit のオフライン解析機能と GeoIP DB 管理機能を Java 25 に移植する。最初の配布物は依存と検知データを同梱した実行可能 JAR とし、検知結果と CLI の互換性を確立した後、jpackage、GraalVM Native Image の順に配布を拡張する。

実行可能 JAR の実装を完了した。実装範囲と検証の根拠は [検証記録](validation.md)、実行方法は [README](../README.md) に記録する。後続の配布方式は初期 JAR と分けて進める。

## 基準と互換性

基準は Go 版 `95148ba4e22d9001d34fbb0e4d59f072efd3e95c`。GeoIP 改修完了後のコード、テスト、辞書、出典を対象とする。元リポジトリは変更しない。

2026-11-21 に Go main `a26ee0f` の追加分を移植した。攻撃別の追加調査ガイドは構造化した JSON リソースとして保持し、判定後の表示情報として付加する。HTML の翻訳は描画ごとの翻訳器に閉じ込め、原文・機械出力・共有テンプレートの状態を書き換えない。既定は日本語、`--lang ja|en` で切り替える。集約の新規キーだけを上限で制限し、GeoIP の起動時警告と解析中の検索失敗を区別する。正確な追加参照 SHA と参照値のハッシュは [baseline.json](reference/baseline.json) に記録する。

CLI オプション・既定値・終了コード・出力先を維持する。JSON `webaudit/2` のフィールド、null と省略の区別、判定・件数・証拠を維持する。HTML は情報とエスケープを維持し、Go のテンプレート記法を Java 向けに移植する。CSV の既存列と数式実行抑止、端末の制御文字除去、出力ファイルを上書きしない動作も互換対象とする。

実装固有のバージョン文字列・配布名と利用者データのアプリ名は Java 版を識別できるようにする。比較では実行日時・入力の絶対パス・実装のバージョン差を区別する。集合である警告等の列挙順を除き、時系列の証拠順は保持する。既知の Go の不具合を見つけた場合は、黙って仕様変更せず利用者へ確認する。

## 再分析した構造

入力はファイル名順に逐次処理し、gzip はマジックで識別する。パーサーは Apache/Nginx のアクセス・エラー、JSON、syslog/journald、NPM、明示正規表現に対応する。必須項目、不正 UTF-8、重複 JSON キー、競合時刻、壊れた要求の扱いを維持する。

独自検知は28シグネチャ、9種類の行動検知と5種類の統計候補、事案関連付け。Hub は63定義中59件対応で4件は未対応を明示する。Aura は25シグネチャと別のケース集計を持つ。各結果を別の集合として出力する。L2 の窓は150秒ずらした2つの5分区間で、厳密なローリング窓へ変更しない。Hub の減衰・distinct・抑制・リセット・5,000イベントごとのGCを再現する。

GeoIP 改修によって、単なるローカル検索から DB の取得・更新・状態確認・復元までが移植対象になった。新しい検索状態、公開版・取得日時等のメタデータ、表示サンプルと独立したIP数、ASN内の類似性ヒントも維持する。GeoIP の値を攻撃スコア・重要度・成否・確信度へ入力しない。

## Java 構成

| 用途 | 採用 |
|---|---|
| 実行・ビルド | Java 25、Maven Wrapper、Maven Shade Plugin |
| CLI | picocli |
| JSON | Jackson 3、重複検出と末尾データ拒否を明示 |
| 正規表現 | RE2/J、全埋め込みパターンのコンパイルと結果をテスト |
| MMDB | MaxMind DB Reader、管理DBは全レコードの役割別検証 |
| HTML | FreeMarker、HTML自動エスケープ |
| CSV | Apache Commons CSV、独自の数式抑止を併用 |
| テスト | JUnit Jupiter、Go版由来の合成fixtureと期待結果 |
| IO・日時・通信 | JDKのNIO、gzip、MessageDigest、java.time、HttpClient |

Spring、DBサーバー、汎用ルールエンジンを必要としない単一Mavenモジュールとする。解析エンジン、入出力、GeoIP検索、DB管理をクラスとして分離する。同梱ルールとテンプレートはクラスパスから開き、JARの物理ファイルを前提としない。解析状態は1実行ごとに生成し、初期版は並列化しない。

## GeoIP の保存先

利用者の決定により Go 版と分離し、アプリディレクトリ名は **webauditJ** とする。

1. 有効な絶対 `XDG_DATA_HOME` があれば、その配下の `webauditJ/geoip`。
2. Windows は絶対 `LOCALAPPDATA` 配下の `webauditJ/geoip`。
3. Linux/macOS は絶対 `HOME/.local/share/webauditJ/geoip`。

空・相対XDGは無視する。Windowsのドライブ絶対パスとUNC share rootを受理する。保存先が決まらない場合、管理コマンドは失敗、通常解析は警告して継続する。

役割ごとに明示指定を最優先し、次に管理DBを使用する。管理manifestが未導入の場合だけ、JARの隣の `geoip/` から固定名・月次名を探索する。破損した管理DBから古い自動DBへ黙って切り替えない。明示DBの不存在・破損は解析前に終了コード2。

## DB 管理とオフライン性

`geoip download|update|status|rollback` を実装する。通信は download/update の取得時だけ。導入済み download、status、rollback、通常解析はオフライン。公式ページから公開月・MMDBリンク・展開後SHA1を読み、時計からURLを生成しない。

HTTPS、公式ホスト・パスの許可リストを初回URLと全redirectへ適用する。プロキシを無効化し、TLSを検証する。45秒のHTTP制限、5分のコマンド制限、redirect最大5、ページ1MiB・圧縮64MiB・展開256MiBを維持する。gzip CRC、配布元SHA1、ローカルSHA256、MMDB構造・全レコードの型と役割を検証する。

Country/ASNを不変世代に配置し、`metadata.json` を一度だけ原子的に置換する。JDK FileLock でwriterと管理snapshotを保護し、失敗・プロセス終了後に再実行可能にする。現世代と前世代を残し、rollback・中断stage回収・孤立世代回収を実装する。旧readerは開いた世代を使い続ける。保持中の旧世代を削除できない場合は後続の更新へ延期する。

検索はIP単位の上限付きLRUで未収録も保持する。peer表とLRUの上限を維持し、超過は部分解析と下限集計を明示する。検索状態はfound / not_found / non_public / invalid_ip / db_not_installed / read_error、役割別のnot_queriedを区別する。ASN類似性は既知ASN、パス、host、技法、5分UTC区間の一致を必要とする。

Windows の MaxMind Java reader は MEMORY モードとする。メモリマップでは破損DBのコンストラクター失敗後にもWindowsのファイルロックが残り、削除できないことをテストで確認したため、利用者の判断で選択した。DBサイズ分のJavaヒープを使う。Linux/macOSはMEMORY_MAPPEDを維持する。実際のDBサイズとキャッシュ以外の保持メモリも性能測定に含める。

## バイトと日時

行・ファイル展開量・証拠の上限はUTF-8バイト単位。巨大行は保持せず次行へ進む。不正なpercent encodingと不正な復号バイトを検知用表現として扱う処理を独立させる。URLDecoderで一括置換しない。大小文字変換はロケールに依存させない。

確定時刻とタイムゾーン不明の壁時計を区別し、不明時刻をUTCとして出力しない。後者はファイル単位で独立し、明示error-timezoneがある場合だけ変換する。IP解析にDNSを使わず、IPv4-mapped IPv6と特殊用途範囲を検証する。

## TDD とコミット

各機能を小さい単位に分け、失敗する振る舞いテストを実行して **RED** をコミットし、通る最小実装で **GREEN**、成功状態を維持する実際の整理を **REFACTOR** としてコミットする。ビルド基盤と設計は別の初期コミット。中間のREDは意図した失敗を含む。

順序は、正規化・入力解析、シグネチャと事案、行動・統計、Hub/Aura、GeoIP検索・集計、DB管理、CLIと各出力、配布検証。発見した互換性の差は先に回帰テストへする。テストでGoやネットワークを必要としないよう、基準版から合成fixture・期待結果を保存する。実DBをGit/JARへ同梱しない。

最終確認は全テスト、合成corpus、上流fixture、実行可能JAR、巨大行・gzip・上限・不正入力・エスケープ・上書き拒否・更新失敗・同時実行・rollback。性能は同一入力の経過時間とメモリを測り、Goの記録済み単発値をJavaの実測値と混同しない。

## 参照

- 基準版の `docs/geoip-database-management.md`、`docs/geoip-testing.md`、`docs/upstream-compatibility.md`
- https://picocli.info/quick-guide.html
- https://github.com/FasterXML/jackson
- https://github.com/google/re2j
- https://github.com/maxmind/MaxMind-DB-Reader-java
- https://freemarker.apache.org/docs/dgui_misc_autoescaping.html
- https://commons.apache.org/proper/commons-csv/

ライブラリと元データのライセンス・出典を配布物へ含める。初期JARにはJava25が必要であり、利用者側のJava導入を不要にする配布は後続のjpackage工程で扱う。
