# v2.0.0 監視機能の移植・検証

移植元は Go WebAudit v2.0.0、コミット `96e3c8a3148d1684d60abac22d3aa2939354e891`。既存のバッチ解析を維持し、watch reader / engine / checkpoint / Hook / CLI を Java 25 で実装しました。

## 確認済み

2026-11-21、Windows / OpenJDK 25 のローカル検証に続き、GitHub Actions の **Windows / Linux / macOS** で Maven `verify` と JAR 検査が成功しました。各 OS で **2,873 テスト**、失敗・エラー・skip は 0。既存の 2,823 件と watch の 50 件を含みます。macOS は arm64 runner で、標準の `/var`・`/tmp`・`/etc` 別名と利用者作成リンクの拒否も検証しています。

CI 対象コミットは `56aa841f8dd89275816f7cb416e994cb3f8f1f03`、結果は [PR #1 の検証 run](https://github.com/mikoto2000/webauditJ/actions/runs/44870124925) を参照してください。Linux amd64 の通信 syscall 禁止試験は **19 実行すべて成功**し、watch の状態保存・復元・ローカル GeoIP を含みます。

- Go v2.0.0 の独立した実行結果を保存した `watch-golden.json` の 4 シナリオ・33 ステップに対し、JSONL の全フィールドを比較。事案 ID、イベント ID、revision、sequence、証拠、成否・確信度、重要度が一致。
- 末尾開始、既存部分行の破棄、追記部分行の連結、オフセット・部分行の復元、rename、停止中の rename と旧ファイル検索、copytruncate、同サイズ以上の書き換えを検証。
- 非再帰ディレクトリ選択、未作成ファイルの検出、空ファイルからの行番号、一時的な読み取り拒否からの回復、不正 UTF-8、行上限、gzip 拒否を検証。
- 遅延・未来イベントの破棄、保持上限、ネイティブ時間窓検知、状態復元後の単調な revision / sequence、成否の更新、close を検証。
- 状態のチェックサム、OS ロック、設定互換性、破損時の停止、明示リセット、`--no-state` を検証。
- Hook の JSON stdin、引用符・空白・バックスラッシュ・シェルメタ文字を含む引数、通知重複抑制と復元、フィルタ、キュー上限、失敗、出力読み捨てを検証。
- Windows Job Object への収容、タイムアウトと停止時の孫プロセス終了を実プロセスで検証。
- JVM 終了 Hook によるチェックポイント保存・ロック解放と、別プロセスでの再開時に同じ事案を再通知しない動作を検証。
- 合成 MMDB の GeoIP を付加しても、その他の検知イベントが変化しないことを確認。
- 実行可能 JAR の Manifest、依存・ライセンス、テスト用 DB / golden データの非混入を `tools/verify_jar.py` で確認。

```powershell
.\mvnw.cmd -o -s .mvn/settings.xml verify
python tools/verify_jar.py
python tools/measure_watch.py --seconds 3 --lines 100
```

worktree で元リポジトリの依存キャッシュを共有する場合は Maven に `'-Dmaven.repo.local=F:/project/webauditJ/.build/repository'` を追加します。

## 短時間の測定

隔離したログ・状態・GeoIP ディレクトリで、実行可能 JAR に空ログを末尾監視させ、起動確認後に合成ログ 100 行を追記しました。Java ヒープ設定は `-Xms32m -Xmx256m`。測定結果は [watch-java-smoke.json](measurements/watch-java-smoke.json) に保存しています。

起動確認まで約 1.10 秒、追記後 3 秒の監視、JSONL 2 イベント、チェックポイント 59,420 バイトでした。入力分割によって中間イベント数は変わります。Windows の測定終了は強制終了（終了コード 1）であり、正常終了の実測値ではありません。正常終了は上記の別プロセス試験で検証しています。CPU・RSS・ヒープのピークや持続スループットは測定していません。

## 未実施と互換性の範囲

ローカル作業環境は Windows です。Linux / macOS の実行と Linux の通信禁止試験は上記 CI で確認しました。複数日耐久・高負荷持続は未実施です。

チェックポイントは Java 版専用形式・`webauditJ/watch` 配下です。Go 版との相互復元はできません。Hook は収容のゲートを持つ補助 JVM を通知ごとに起動するため、Go 版と起動コストが異なります。実行可能 JAR の native access は Manifest で有効化します。

通常監視はローカル処理のみ。Hook に渡した実行ファイルの副作用、クラッシュ境界の重複・通知欠落、polling / copytruncate 競合、Unix で明示的に session を離脱する子孫についての制限は [監視ガイド](watch.md) を参照してください。
