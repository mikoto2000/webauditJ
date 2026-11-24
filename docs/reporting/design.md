# Java版報告書出力の移植設計（Phase 0）

原要求は[requirements.md](requirements.md)。先に実装・検証したGo版は`mikoto2000/webaudit`のPR #30–36、最終merge `c3450731912e2e3e217198597adf98d680fb6f1e`。Java版の移植開始時点は`bdc9cda`。Go版の出力契約、件数定義、未知情報の扱い、安全性を引き継ぎ、Javaの既存検出器を再利用する。Go実行ファイルを呼ぶ方式やネットワークサービス依存にはしない。

## 現行実装との対応

| 責務 | 既存Java実装 | 移植時の変更方針 |
|---|---|---|
| CLI/上限/Geo選択 | Main、Options | 明示report-dir、任意調査metadata、spool/output上限、マスク解除flag。従来-o/formatと排他 |
| 入力/形式/診断 | LogInput、LogParser、Event | optional bundle capture。既存streamから物理行/除外/parse/期間/項目を観測、parser branchは内部属性 |
| 署名 | Signatures、Normalizer、rules.json | 同じdetect結果を観測。独自の再検出や類似regexを追加しない |
| 行動/統計 | Behavior、Signal | 終了時の同じsignalsと実際の母数状態を利用。spoolの関連requestと照合 |
| 事案/成否 | Correlator、Outcomes、Investigations | 既存key生成を共有化しWA-IDを維持。事実/推定/未知/条件付き影響、攻撃別案内を再利用 |
| 独立engine | Upstream、AuraSignatures、AuraAnalysis | 既存accepted membershipをtokenで記録、emitされたgroupのみ解決。独立のまま関連IDを保持 |
| 地理/ASN | GeoIP、GeoAnalysis、GeoCorrelations | 既存lookup/DB metadata。国・ASNだけで悪性と判断しない |
| 既存出力 | Reports、report.ftlh、ReportLanguage | 単一出力を維持し、bundle用共通modelと別templateを追加。標準escape/CSV/JSONを再利用 |

既存のmapモデルを共通report modelに内包する。新規クラスをmetadata/lifecycle、coverage、request spool、statistics、presentationへ責務分割する。コア実装は同じパッケージから呼び、package-private optional observerでwatchや従来APIへの影響を限定する。新しい依存ライブラリは不要。

## 出力と識別子

`webaudit/investigation-1`共通JSON、`webaudit/manifest-1`、11章の日英HTMLと、inventory/rules/coverage/findings/detections/suspicious/related/recommendations/statistics/diagnosticsのCSV別紙を明示モードで生成する。Go版と同じ単位・enum・列を基本にする。言語固有build情報・既存解析モデルの意味のある差は保持し、同値でない値を合わせるために捏造しない。

Requestは正規化済み原本パス由来FILE-IDと元行番号から生成する。同じ文字列でも別file/lineは別観測。アプリケーションのnative request IDとは区別する。Findingは既存CorrelatorのID、Detectionはengine/rule/期間/group、CoverageとRecommendationは別ID。原本hashはgzipを含む保存状態のbytesを前後照合する。全観測をメモリに保持せず、上限付きprivate JSONL spoolで解析時の値と正規化・一致・source tokenを固定する。

終了時に保持された検出と照合してCSVを逐次生成する。Hub distinctやblackholeで不成立の候補を検出へ格上げしない。Auraのcase集計やWA集計は関連証跡で、全group内requestを不審としない。直接検出の一意観測と各rule一致/保持groupを区別する。engine間の事案自動統合はせず、request IDsで重複を追跡する。

## 完全性と資源

全アクセス統計はspool書込み前の既存streamから計数し、spool上限に達しても母数を維持する。不審フラグは終了後の一意観測照合から計数する。次元別キー・文字列・timeline・case統計は既存上限に制限し、other・lower_bound・unavailableを明示する。既知の0と欠損nullを区別する。coverageの評価状態/完全性/hit有無は独立。ルール未対応・無効・必要field不足・母数不足・未実施をno detectionにしない。

ディスクはspool/output各既定1 GiB、メモリは保持keys/findings/evidenceとbounded JSON変換に比例する。Java版のCPU・heap・diskはPhase6で別途測定し、Go実測を流用しない。終了時のspool削除、失敗時のINCOMPLETE marker、排他的新規出力を保証する。元ログや既存成果物は上書きしない。

## 表示と安全性

HTMLは外部script/CDN/imageを使わず、ラベル・件数付きグラフ、11章目次、一覧/詳細/戻り、coverage/rule参照、印刷CSSを備える。代表ログと全件CSVは明確に分け、HTML件数を制限する。共通modelの数値をHTML/JSON/CSVへ渡し、表示時に別検出や別集計を行わない。

秘密query/header/JSON値は解析後に既定マスクする。元FILE-ID/line参照はマスク前に作る。明示include-sensitive-evidenceで解除できるがcontrol/Bidi可視化は解除しない。全個人情報の完全匿名化は保証しない。FreeMarker autoescape、CSV formula guard、Jacksonを使い、任意の入力をテンプレートや実行コードへ変換しない。manifestにregex本文や全argvを残さない。

severityは既存優先度、検出確度は独立未評価の場合unknown、既存outcome/confidenceはその意味を維持する。scoreを校正確率にしない。HTTP200/403/404のみで侵入や失敗を確定しない。本文専用・reputation等の未対応観点は表に残す。

## 実装フェーズ

| Phase | 成果と主な検証 |
|---|---|
| 0 | 現状対応・本設計・要求表・既存基準ビルド。実行コード変更なし |
| 1 | bundle CLI/lifecycle、inventory/hash/settings/rules fingerprint/manifest/diagnostics、排他・gzip・失敗・互換性 |
| 2 | 全観点と全既存rule、実際のfield/母数、partial/unsupported/unable/no-hitの独立性 |
| 3 | request/detection/finding、bounded spool、source exact token、全件/関連CSV、遅延集計、変更/上限/削除 |
| 4 | 全体/不審/時系列/数値/Geo統計、0/欠損、cardinalityとtimebin上限、共通母数 |
| 5 | 共通summary/assessment/recommendation、11章日英HTML、graph/navigation/print、マスク/制御文字/注入 |
| 6 | 全契約統合、Go対比、offline JAR、Java固有性能/heap/disk、日英sample、READMEと最終対応表 |

各phaseで最新mainから専用worktree、短いRED/GREEN/整理commit、全テスト/必要検証、セルフレビュー、PR、最新headのCI/merge条件確認、通常merge、元main更新、worktree/当該localbranch削除を行う。Phase0は文書のみのためRED/GREEN対象なし。CIや権限不足を迂回しない。利用者の未commit変更を触らない。
