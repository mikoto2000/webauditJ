# 要求対応表（Java移植）

原文は[requirements.md](requirements.md)、設計は[design.md](design.md)。Go版Phase0–6完了後に着手する。以下は移植開始時点の差分であり、各phaseで実装・テストを追記する。

| 要求 | 開始時点 | 対応phase | 完成時の検証根拠 |
|---|---|---|---|
| §1–2 offline/batch/既存再利用/互換性 | 既存解析対応、bundle未対応 | 全 | 全既存tests/JAR/offline guard |
| 第1章 調査概要/metadata/summary | 部分 | 1,3,4,5 | 任意metadataと共通summary、単位/quality |
| 第2章 対象/原本inventory/hash | 部分 | 1,5 | gzip保存bytes、before/after、field/timezone/diagnostics |
| 第3章 実装に即した方法/ルール | 部分 | 1,2,5 | 実効settings/条件/limits |
| 第4章 severity/confidence/outcome | 既存成否対応、新軸説明未対応 | 2,5 | 異なる意味を変換しない、unknown |
| 第5章 全アクセス/不審統計/graph | 部分 | 4,5 | 共通分母、0/null、Geoなし、timeline |
| 第6章 全観点coverage | 未対応 | 2,3,5 | 未対応/部分/不能/未実施/no-hitを分離 |
| 第7章 事案/独立検出一覧 | 旧HTMLに一覧あり | 3,5 | request union、別単位、navigation |
| 第8章 詳細/全証跡/調査案内 | 代表証跡/旧案内のみ | 3,5 | 元行参照、事実/推定/未知/条件付き影響 |
| 第9章 総合評価 | 未対応 | 4,5 | 根拠のある共通集計/参照、存在/侵入の非断定 |
| 第10章 一般制約/発生制約 | 部分 | 1,2,5 | input別状態、冒頭部分解析 |
| 第11章 事案別推奨 | 旧案内あり | 3,5 | ID/理由/対象/時刻/証拠/優先度、調査と予防 |
| §4 全件不審/関連/遅延検出 | 未対応 | 3 | exact membership、別観測、重複engine、spool cap |
| §5 共通model/stable ID | 旧map modelのみ | 1–5 | 共通JSON/HTML/CSV契約 |
| §6 bundle/manifest/全artifact hash | 未対応 | 1–5 | 排他、新規dir、失敗marker、原本不変 |
| §7 日英/11章/リンク/印刷/負荷 | 旧HTML日英のみ | 5,6 | 全anchor、静的文言、件数制限、サンプル |
| §8 出力安全性/マスク/資源 | 既存escape等あり | 1,3,5,6 | hostile evidence、制御文字、数式、秘密、path/temp |
| §9 正確性/完全性/集計関係 | 部分 | 全 | 一意観測・rule/engine・0/null/lowerbound、共通値 |
| §10–11 フェーズ/TDD/PR/CI/後片付け | 今回開始 | 全 | PRと作業記録（成果物外） |
| §12 必須テスト全項目 | 既存解析testsあり | 1–6 | 契約/統合testsと最終test matrix |
| §13–14 完了/最終報告/測定 | 未完了 | 6 | Java実測/日英sample/README/本表/PR状態 |

未対応や評価不能な調査観点を新規検出器で無理に埋めず、実際の支援範囲として開示する。Java固有の実装差・制限・未検証は完成時にも明示する。


## Phase 1 実装・検証

`Bundle`/`BundleWriter`/`BundleOptions`/`BundleCapture`に原本inventory・前後hash・実効settings・秘密regexのhash・rules fingerprint・build・全artifact hash・診断・排他新規出力・INCOMPLETEを移植。`LogInput`のoptional observerで既存streamを再利用し、`Event.format`は非公開属性としてlegacy JSONへ出さない。実際に通ったparser branchとtimezone offset/fieldsを記録する。

BundleTestはgzip原本と3種類の行、全成果物hash、既存出力拒否、原本変更、出力容量上限/失敗marker、CLI metadata/排他、dedup/空/不読、秘密regex、Long.MAX_VALUE上限、hash上限を超える原本増大を検証する。REDでは未実装classによるコンパイル失敗を確認。追加の巨大上限テストは修正前の算術overflowで停止しなくなり、該当テストJVMだけを特定して終了した。修正後は5テスト成功。今後の再発時に停止し続けないよう2秒のpreemptive timeoutも設ける。

Phase1のHTMLは既存templateを使う暫定表示であり、提出用11章と全件CSV/coverage/統計は後続phase対象。新しい検出器・watch変更・依存追加なし。機密値マスクはPhase5で移植する。


## Phase 2 実装・検証

`BundleCoverage`にGo版と同じ41観点、全既存のnative/行動/統計/Hub/Aura署名/Aura集計/Geoのmetadata・条件・必要項目・IDを移植した。`report-aspects.json`と`report-aggregate-rules.json`は移植元の報告書契約の静的説明であり、検出器ではない。native/Hub/Auraの実際の検出結果をoptional observerで受け、Behavior内部の実際のbaseline/peer数から評価可能性を取得する。AuraAnalysisは実装と同じaccess-log範囲だけを適用母数とする。

カバレッジのevaluation/status/complete/has_detectionsを独立保持し、母数不足・field不足・入力部分解析・部分支援・未対応・Geo未実施を区別する。観点内の署名一致requestはunion、rule一致数は別。Hub等のmatched_candidatesはフィルタ候補であり成立検出と別にし、全件関連付け前に不確かな一意request数を補完しない。旧解析モデル・旧HTML/CSVを変更しない。

BundleCoverageTestのREDでcoverage未出力を確認し、GREENで9件のbundle契約テストが成功。全rule列挙、部分hit、未対応、UA不足、Geo未実施、正常no-hit、統計母数不足、一意request対複数ruleを検証する。原本来歴と全artifact hashも再検証する。

Phase2セルフレビューで、国DBのみ利用時にASN類似性を評価済みno-hitと扱わない回帰テストを追加した。対応するGo版にも同じ前提確認の補正を別PRで反映する。


## Phase 3 実装・検証

`RequestSpool`で解析時のEvent/正規化/native hit/source token/元ID/Geoを上限付きprivate JSONLへ固定し、`BundleRequests`から全不審・関連・検出・保持事案CSVを逐次生成する。Correlatorの既存keyを共通化して実際に保持されたfindingへ照合する。Hubはdistinct適用後のbucket tokenを記録し、実際のemitだけを解決する。抑制されたbucket候補は検出にしない。Aura署名のaccepted groupも同じ方式。AuraAnalysisは元UA digestを非公開キーとして保持し、clipped表示値で誤関連させない。

native WB/WSとAura case集計は原則related。WS-size/url-sizeは実際の元行へのdirect。requestを複数engine/ruleで重複計上しない。source token・file/line point・IP/host/短いwindow bucket・UA/hourのindexで、全requestに全caseを総当たりしない。未知timezoneはpublic時刻nullを維持し、spool内の実装用時刻を外部のUTC事実へ転用しない。

`ObservationMetrics`は事案内request union、direct/related、検出、status、method64、URI8x1024、bytesを保持し、case timelineは後続の統計モデルで追加する。未保持case/compacted遅延field/spool上限/入力不完全性は全件性に反映する。原本は再走査・変更しない。完成失敗時markerを残す。

BundleRequestsTestで代表8件を超える25同文別観測、600通常関連、複数engine/rule、一意ID、成否非転記、spool1byteで解析継続/下限/削除、終了時WS-ip、既存Hub matcherに小さいbucket設定を与えdistinct/blackholeを検証する（設定はfinallyで復元）。REDで未出力CSVを確認し、GREENで全件関連付けが成功した。

Phase3追加レビューでは1970年以前のnative時区分とAura UTC時区分を索引で分離するRED/GREEN回帰を追加した。元のエンジンの時区分を変更せず、関連証跡の取りこぼしを補正する。Go版は既に別scopeの索引を利用しており、同じ問題はない。


## Phase 4 実装・検証

`BundleStatistics`はspool書込み前に全観測を計数し、全件照合のdirectフラグを一度だけ不審集計へ反映する。既存Geo lookupを再利用する。次元はmaxKeys/各label長/other、地理のunique IP組は共有maxKeysに制限する。`BundleTimeline`を全体/事案で共有し、UTC分/時/日等へ統合、未知時刻/省略を別扱いにする。durationは既存parserが実際に読んだrequest_time/custom duration_secondsを内部属性に追加し、旧Event JSONへは出さない。

`BundleNumeric`は有効/欠損/不正を排他的に数え、既知0を保持し、NaN/Inf/負値を採用しない。合計overflowはnull+quality。数式やraw値の検出処理は変更しない。全件母数と、不完全な不審件数の品質はstatistics row/CSVでも別の列にし、spool打切りを単体別紙でも開示する。移植元Go版にもこの数値分類・品質表示の補正を別PRで反映する。

BundleStatisticsTestは正常+不審の全母数/次元合計、size0/mean、duration欠損/0/不正/overflow、spool1byte後の全件母数、cardinality2と広い期間のtimeline、Geoと国別一意IP/不審件数を検証する。REDでstatistics未出力とCSV品質列不足を確認し、GREENで契約テストが成功した。
