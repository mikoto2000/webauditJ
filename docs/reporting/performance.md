# 報告書生成の性能・資源使用量（Java）

2026-11-24、Windows 11 amd64、JDK 25+36-3489、24論理CPU、各プロセス`-Xmx1g`で実測した。各条件1回を順番に実行した開発機の合成ログ測定であり、中央値や本番保証ではない。JVMは条件ごとに新規起動し、事前の解析ウォームアップなし。デスクトップ上の他プロセスの影響も含む。同時に本作業のテストや別の測定を実行しない。Go版の測定はGoリポジトリの同名文書を参照する。

`tools/ReportBenchmark.java`は16個のIP、32パス、1秒ごとの時刻を用い、混在条件だけ5件ごとに`/.env`への404を含める。通常条件にも統計・探索候補が成立し得る。既存既定設定（maxKeys=4096、maxFindings=2000、evidence=32 MiB）、成果物上限256 MiB。baselineは同一コードの従来Engine.analyze経路で、追加bundle処理を無効にする。入力生成時間は除き、解析から成果物の完成・sampler終了までを計る。post-GC測定は経過時間の外である。

| 条件 | 行数 | 入力bytes | 経過秒 | 行/秒 | 最大サンプルJava heap bytes | 終了後GC時heap bytes | spool bytes | 最終成果物bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 従来解析・通常 | 100,000 | 9,412,500 | 44.692 | 2,238 | 349,179,688 | 6,395,584 | 0 | 0 |
| bundle・通常・spool16 MiB | 100,000 | 9,412,500 | 52.436 | 1,907 | 356,217,112 | 9,580,144 | 16,776,670 | 982,925 |
| bundle・20%混在・spool256 MiB | 100,000 | 9,258,750 | 74.387 | 1,344 | 398,033,248 | 65,756,704 | 99,657,502 | 77,747,601 |
| bundle・20%混在・spool16 MiB | 1,000,000 | 92,587,500 | 650.756 | 1,537 | 376,759,592 | 61,863,912 | 16,777,111 | 45,645,373 |

通常10万行のbundleは従来解析より約17.3%長かった。追加I/O・全統計・snapshot・hash・マスク・別紙・HTMLのコストであり、従来の単一出力モードにはこの経路を追加しない。

JMXの使用済みJava heapを10ms間隔で採取した最大値で、未回収garbageも含み、瞬間ピークを取り逃がし得る。終了後に共通reportを生存させてSystem.gc後のheapも記録したが、GC実行の厳密保証やOS RSSではない。CPU時間・native memory・OS全体RSSは測定していない。heap_committed/max_heapの生値もJSONに残す。全観測をRAMに保持せず、設定されたキー・検出事案・証跡と一時シリアライズに依存する。設定を増やせばメモリは増加する。有限のサンプル測定だけで任意入力の性能は保証しない。

混在100万行でもspoolは16,777,111 bytes ≤ 16,777,216 bytesだった。全観測数は1,000,000で、spool打切り後も解析・全アクセス統計を継続した。最終成果物とspoolを加えた保守的ディスク上界は62,422,484 bytes。両最大値が同時にあると仮定した上界で、実測ピークディスクではなく入力も含まない。混在10万行の同上界は177,405,103 bytes。sampled spoolの最大値と最終spoolバイト数も別に記録する。正常終了前にprivate spoolを削除する。異常中断はINCOMPLETE付き出力を未完了の機密資料として扱う。

全条件で全行をパースしたが、既定の集計キー上限に達しcomplete=falseだった。混在条件は保持事案・推奨上限にも達した。16 MiB条件はさらにspoolを打ち切り、全件証跡と不審集計は下限扱いとなる。256 MiB条件は全snapshotを書けたが、解析事案の保持不完全性からevidence_complete=falseを維持した。警告全文は[performance-data.json](performance-data.json)に記録する。完全な全件攻撃分類の測定と混同しない。

測定時のfeatureはPhase6のbuild identityを含む22517bf、ツールはb1fa76c。後の変更は公開sample・テスト・利用文書であり、検出器を変更していない。

再現例（Windows。各条件を同時実行しない）:

```powershell
javac -cp target/webauditJ.jar -d .build/report-benchmark tools/ReportBenchmark.java
java -Xmx1g -cp '.build/report-benchmark;target/webauditJ.jar' io.github.mikoto2000.webaudit.ReportBenchmark 100000 analysis false 16777216
java -Xmx1g -cp '.build/report-benchmark;target/webauditJ.jar' io.github.mikoto2000.webaudit.ReportBenchmark 100000 bundle false 16777216
java -Xmx1g -cp '.build/report-benchmark;target/webauditJ.jar' io.github.mikoto2000.webaudit.ReportBenchmark 100000 bundle true 268435456
java -Xmx1g -cp '.build/report-benchmark;target/webauditJ.jar' io.github.mikoto2000.webaudit.ReportBenchmark 1000000 bundle true 16777216
```

Unixではclasspath区切りを`;`から`:`に変更する。ツールはOSの新規temporary directoryを作成し、自身の作った合成入力と出力だけを含有範囲確認後に削除する。sampler/JMX/file stat自体の負荷も含む。入力hashや資源制限は改変の完全なロックや任意の敵対的入力への時間制限を保証しない。
