# 要求対応表（Java移植）

原文は[requirements.md](requirements.md)、設計は[design.md](design.md)。Go版Phase0–6完了後にJava版Phase0–6を移植した。以下に実装結果を示し、検証根拠を各phaseと末尾の統合テスト表に記録した。利用方法・成果物・意味と制限は[output.md](output.md)、実測値は[performance.md](performance.md)を参照。

| 要求 | 実装結果 | 対応phase | 検証根拠 |
|---|---|---|---|
| §1–2 offline/batch/既存再利用/互換性 | 対応済 | 全 | 全既存tests/JAR/offline guard |
| 第1章 調査概要/metadata/summary | 対応済 | 1,3,4,5 | 任意metadataと共通summary、単位/quality |
| 第2章 対象/原本inventory/hash | 対応済 | 1,5 | gzip保存bytes、before/after、field/timezone/diagnostics |
| 第3章 実装に即した方法/ルール | 対応済 | 1,2,5 | 実効settings/条件/limits |
| 第4章 severity/confidence/outcome | 対応済 | 2,5 | 異なる意味を変換しない、unknown |
| 第5章 全アクセス/不審統計/graph | 対応済 | 4,5 | 共通分母、0/null、Geoなし、timeline |
| 第6章 全観点coverage | 対応済 | 2,3,5 | 未対応/部分/不能/未実施/no-hitを分離 |
| 第7章 事案/独立検出一覧 | 対応済 | 3,5 | request union、別単位、navigation |
| 第8章 詳細/全証跡/調査案内 | 対応済 | 3,5 | 元行参照、事実/推定/未知/条件付き影響 |
| 第9章 総合評価 | 対応済 | 4,5 | 根拠のある共通集計/参照、存在/侵入の非断定 |
| 第10章 一般制約/発生制約 | 対応済 | 1,2,5 | input別状態、冒頭部分解析 |
| 第11章 事案別推奨 | 対応済 | 3,5 | ID/理由/対象/時刻/証拠/優先度、調査と予防 |
| §4 全件不審/関連/遅延検出 | 対応済 | 3 | exact membership、別観測、重複engine、spool cap |
| §5 共通model/stable ID | 対応済 | 1–5 | 共通JSON/HTML/CSV契約 |
| §6 bundle/manifest/全artifact hash | 対応済 | 1–5 | 排他、新規dir、失敗marker、原本不変 |
| §7 日英/11章/リンク/印刷/負荷 | 対応済 | 5,6 | 全anchor、静的文言、件数制限、サンプル |
| §8 出力安全性/マスク/資源 | 対応済 | 1,3,5,6 | hostile evidence、制御文字、数式、秘密、path/temp |
| §9 正確性/完全性/集計関係 | 対応済 | 全 | 一意観測・rule/engine・0/null/lowerbound、共通値 |
| §10–11 フェーズ/TDD/PR/CI/後片付け | 実装・検証済、最終CI/マージはPhase6 PR参照 | 全 | PRと作業記録（成果物外） |
| §12 必須テスト全項目 | 対応済 | 1–6 | 契約/統合testsと最終test matrix |
| §13–14 完了/最終報告/測定 | 実装・検証済、最終CI/マージはPhase6 PR参照 | 6 | Java実測/日英sample/README/本表/PR状態 |

未対応や評価不能な調査観点を新規検出器で無理に埋めず、実際の支援範囲として開示する。Java固有の実装差・制限・未検証は完成時にも明示する。

「全観点を報告する要求」は実装済みであり、「全観点の検出器を新規に実装した」という意味ではない。本文専用攻撃・IP reputationは未対応、入力項目・母数が足りない観点は評価不能、GeoDBなしは未実施として出力する。検出確度は未校正のためunknown、独立検出の侵入成否も未評価を維持する。これらを無検出や安全と表示しない。


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


## Phase 5 実装・検証

`BundlePresentation`が共通summary/assessment/recommendationを作る。既存Investigationを再利用し、事実/推定/未知/条件付き影響・正常アクセスの可能性・追加調査/予防策を分離する。metadataは任意、既存severity/outcome/confidenceの意味を変更しない。request/検出/group/事案件数を別単位にし、source検出を安易に統合しない。

`BundleHTML`/`investigation.ftlh`は11章、日英、全体/事案/独立検出の一覧・詳細・戻り・rule/coverage/関連リンク、raw代表ログ、CSVへの参照、offline meter、print CSSを提供する。共通値のread-only viewで新しい検出を行わない。HTML量を固定上限で制限し、完全保持分はCSV/JSONで提供する。source_indexはマスク後のsourceモデル参照にも使用する。

`BundleMask`はRE2/Jの線形パターンとvisible controlsで共通モデルとCSVを一貫して変換し、FreeMarker autoescape/既存formula guard/Jacksonを再利用する。元FILE-ID/line参照はマスク前に作り、raw値は解析前に変えない。信頼されたbuiltin condition/filter/patternは再現性のため元の値を保持する。完全な匿名化は保証しない。明示sensitive opt-outと常時control/Bidi可視化を分離する。

BundlePresentationTestのREDで11章/マスク/制御文字と未翻訳ラベルを確認し、GREENでja/en、全fragment先の存在/重複禁止、共通summary・推奨CSV、全artifactの秘密値、元ログ不変、opt-out、制御文字、日本語固定ラベル全件、マスク後のファイル名衝突でもsource refsが区別可能なことを確認。事案CSVのattack_scoreを実際の旧モデルキーと一致させた。原本/coverage/Geo関連参照は索引化し、各caseで全対象を走査しない。

画面の目視確認はGo版と同じローカルfile URL制限により未実施。静的テンプレート・全anchor・escape・offlineリソースと契約の自動検証で確認し、最終サンプルと性能測定はPhase6へ続ける。

## Phase 6 統合検証・完成時の対応

`BundleIntegrationTest`で複数ファイル・ローテーション・gzip・逆順時刻の700観測を照合し、同文の別観測を失わず、共通JSON/summaryの一意件数と一致することを検証する。HTTP200でも侵入成功へ格上げしない。配布JARの自己fingerprintをmanifestに記録し、classes実行では非取得を明示する。既存の検出器・parser・normalization・Correlator・SourceMatcher・Geo lookup・Investigation・escape/serializerを再利用し、新規検出器・依存・watch変更を加えない。

共通モデルは`webaudit/investigation-1`、manifestは`webaudit/manifest-1`。旧`webaudit/2`を`analysis`に保持し、inventory/coverage/rules/evidence/statistics/summary/assessment/recommendationsを追加した。内部Eventのformat/duration/observer/tokenは旧Event JSONに漏らさない。request IDは元file+line観測のIDである。

| §12 必須テスト観点 | 主な実行根拠 |
|---|---|
| 正常のみ/不審のみ/混在/空 | BundleCoverageTest.preservesNoHitAndInsufficientBaseline、BundleStatisticsTest.countsAllAccessesAndKeepsKnownZeroSeparateFromMissing、BundleTest.disclosesDedupEmptyUnreadableAndPrivateSettings |
| 複数rule/engine・同文別観測 | BundleRequestsTest.preservesFullDistinctObservationsAndSeparatesRelated、BundleCoverageTest.keepsAspectRequestUnionSeparateFromRuleHits |
| 複数file/rotation/gzip/逆順 | BundleIntegrationTest.preservesRotatedGzipOutOfOrderEvidenceAndSharedCounts、BundleTest.inventoriesOriginalGzipAndSealsEveryArtifact |
| parse不能/必要field不足/不読 | BundleTestのinventory/unreadable tests、BundleCoverageTest.separatesPartialHitUnsupportedUnableAndEveryRule |
| GeoDB有/無/国DBだけ | BundleStatisticsTest.recordsGeoAndInvalidDurationWithoutInventingValues、BundleCoverageTest.doesNotClaimASNSimilarityWasEvaluatedWithOnlyCountryDatabase、既存GeoIP tests |
| 上限/原本変更/遅延統計 | BundleTest.marksChangedInputsAndFailedOutputWithoutChangingOriginal、BundleRequestsTest.disclosesSpoolTruncationAndKeepsFullAnalysisCounts/associatesEndOfAnalysisStatisticalSignals |
| 成否不明/200/403/404 | 既存CorrelatorTest/InvestigationTest、700観測統合のconfirmed_success禁止、requestへの成否非転記 |
| HTML/CSV/JSON injection/秘密/controls | BundleIntegrationTest.escapesHostileEvidenceInHTMLCSVAndStructuredJSON、BundlePresentationTestのmask/opt-out/controls/filename collision |
| HTML/JSON/CSV集計・日英・リンク | BundlePresentationTest.rendersAllChaptersNavigationAndCommonRecommendationsInBothLanguages/translatesEveryStaticTemplateLabel、全fragment存在と重複禁止 |
| 公開サンプル・全hash | BundleIntegrationTest.publishedSamplesKeepArtifactHashesAndSharedSummary、tools/verify_jar.pyのJAR SHAと成果物全hash |
| 大規模ログ・メモリ・一時領域 | tools/ReportBenchmark.java、performance.md、生値JSON。既定上限での部分解析も記録 |
| offline・CLI/output/watch互換 | 全既存テスト、配布JAR単独実行、Linux全thread seccomp guard下のja/en bundle/全hash/従来出力/watch |

ローカルWindowsで全Maven verify（2,908 tests、failure/error/skip各0）、JAR単独実行と自己/成果物hash検査、静的差分確認が成功し、Linux/macOS/Windowsの全テストとLinuxのネットワーク禁止検証をPR CIで実行する。画面の目視確認は環境のローカルHTML制限で未実施。自動検証を目視確認の代わりに実施したという限界を残す。

同じ実ファイルパスの`examples/sample.log`をGo最新版とJava配布JARで解析し、summary全項目・native事案のIP/rule/count/severity/score/outcome・不審/関連CSVの全request ID集合・9次元の全行を比較して一致した。9観測、直接不審8観測、検出16件（native8、Aura署名3、Aura集計5、Hub0）、native事案4件。日時・buildと独立groupのopaque IDのbyte一致は比較対象ではない。既存EngineTestのGo全報告golden検証も維持する。

秘密マスクは一般的パターンへの対応で、全個人情報の匿名化ではない。HTML本文は事案各100件等の上限付き、別紙は全保持データである。保持設定・spool・出力上限・入力不完全性による部分解析を隠さない。source group IDは既存Java内部digestの表現差があるためGoのopaque IDと同一bytesを保証せず、共通の意味・一意観測と参照関係を検証する。任意のOS/DB監査や本文・実際の損害を捏造しない。

## フェーズPRと作業状態

Go版を先に完了した後、Java版を順に実装した。各フェーズは専用worktreeとRED/GREENコミットを使用し、前フェーズのCI成功・通常マージ・元main更新・worktreeとローカル作業branchの削除後に次へ進んだ。最終フェーズの最新CI/マージ状態はPRの状態を参照する。

| Phase | Go版 | Java版 |
|---|---|---|
| 0 | [#30](https://github.com/mikoto2000/webaudit/pull/30) マージ・CI成功・削除済 | [#2](https://github.com/mikoto2000/webauditJ/pull/2) マージ・CI成功・削除済 |
| 1 | [#31](https://github.com/mikoto2000/webaudit/pull/31) マージ・CI成功・削除済 | [#3](https://github.com/mikoto2000/webauditJ/pull/3) マージ・CI成功・削除済 |
| 2 | [#32](https://github.com/mikoto2000/webaudit/pull/32) マージ・CI成功・削除済 | [#4](https://github.com/mikoto2000/webauditJ/pull/4) マージ・CI成功・削除済 |
| 3 | [#33](https://github.com/mikoto2000/webaudit/pull/33) マージ・CI成功・削除済 | [#5](https://github.com/mikoto2000/webauditJ/pull/5) マージ・CI成功・削除済 |
| 4 | [#34](https://github.com/mikoto2000/webaudit/pull/34) マージ・CI成功・削除済 | [#6](https://github.com/mikoto2000/webauditJ/pull/6) マージ・CI成功・削除済 |
| 5 | [#35](https://github.com/mikoto2000/webaudit/pull/35) マージ・CI成功・削除済 | [#7](https://github.com/mikoto2000/webauditJ/pull/7) マージ・CI成功・削除済 |
| 6 | [#36](https://github.com/mikoto2000/webaudit/pull/36) マージ・CI成功・削除済 | Phase6検証PR（最終回答にURL） |
| 移植照合補正 | [#37](https://github.com/mikoto2000/webaudit/pull/37)、[#38](https://github.com/mikoto2000/webaudit/pull/38) マージ・PR/main CI成功・削除済 | ASN評価前提・数値の排他的分類と不審件数品質を移植内で共通化 |

Go版Phase5のmain CIは既存PowerShell起動待ち5秒タイムアウト後に該当jobを1回再実行して成功した。Java版はPhase5までPR/main CIの成功を確認済み。作業記録は成果物外の`.workflow/reporting/state.md`に保持する。
