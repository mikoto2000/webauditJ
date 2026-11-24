# 開発・検証

JDK 25、Maven Wrapper、Python 3.11 以上（補助検証用）を使います。通常の Maven テストには Go・ネットワーク・実 GeoIP DB は必要ありません。初回の Wrapper と依存取得には通信が必要です。

```powershell
$env:JAVA_HOME='C:\Java\jdk-25'
.\mvnw.cmd -s .mvn/settings.xml verify
python tools/verify_jar.py
```

```sh
./mvnw -s .mvn/settings.xml verify
python3 tools/verify_jar.py
```

取得後は Maven に `-o` を加えるとオフラインで検証できます。`.mvn/maven.config` はローカルリポジトリを `.build/repository` に設定します。Wrapper の配布先も隔離する場合は `MAVEN_USER_HOME` をこのプロジェクトの `.build` に設定してください。`target/`、`.build/`、`.workflow/` は追跡しません。

## TDD と参照値

振る舞いを失敗するテストへ落とし、RED を実行・コミットします。通る最小実装を GREEN、成功を維持する整理を refactor として別々にコミットします。履歴中の RED コミットは意図してテストに失敗します。

Go 基準版から保存した parser/detection/upstream/corpus の期待値は `src/test/resources/*-golden.json` にあります。件数と SHA-256 は `docs/reference/baseline.json`、再生成手順は [tools/reference/README.md](tools/reference/README.md) に記録しています。通常のテストは保存済み期待値を比較します。基準版を更新するときは差分をレビューし、期待値を一括で追従させるだけで互換性を判断しないでください。

`src/test/resources/geoip/` の MMDB はテスト用合成データで、製品 JAR へ含めません。DB 管理テストは一時ディレクトリと偽の配布元を使い、失敗注入・別プロセス間ロック・強制終了からの回復も検証します。Windows の AppContainer のようにディレクトリ rename を制限する環境では、通常のファイルシステム権限でテストを実行してください。

## 配布と通信の検証

`python tools/verify_jar.py` は Manifest、同梱リソース・ライセンス、テスト用 DB/期待値の混入がないことを確認します。JAR の SHA-256 も出力します。

Linux amd64 / JDK 25 で次を実行します。

```sh
python3 tools/verify_offline.py
```

テスト専用 Java agent が JVM/libc 初期化後、アプリケーションの main より前に全 JVM スレッドへ seccomp TSYNC を適用します。その後の socket/connect/send/receive 等はカーネルがプロセスを終了させます。最初に通信試行で終了する自己検証を行い、続いて 15 通りの通常解析・管理 DB 操作を実行します。JVM 起動前からの禁止ではありません（libc の nscd 探索等はガード開始前）。`--enable-native-access` はこのテスト用 agent のためだけで、製品の実行には不要です。

実配布元の検証は、通常テストとは別に、空の専用 `XDG_DATA_HOME` で `geoip download/status/update` を実行します。利用者の既存 DB や Go 版の保存先を検証に使わないでください。

## 性能測定

ビルド済み JAR に対して実行します。

```sh
python3 tools/benchmark.py --lines 100000 --output .workflow/performance.json
python3 tools/benchmark.py --lines 100000 --country /path/country.mmdb --asn /path/asn.mmdb --output .workflow/performance-real.json
```

反復/異なる IP、IPv4/IPv6 混合の合成ログを作り、各々 GeoIP 無効/有効で別 JVM を起動します。既定 DB は小さい合成 DB です。実 DB のメモリ負荷は明示指定して測ります。入力生成と JVM 起動時間を除き、DB オープンと解析を計時します。解析には最初のクラス初期化と JIT が含まれ、ウォームアップ済みスループットではありません。

Java ヒープは `-Xms64m -Xmx512m`、ヒープ使用量は約 10ms 間隔、プロセスメモリは約 50ms 間隔で測ります。サンプル最大値は瞬間ピークの保証ではありません。異なる IP のケースは既定キー上限に達するため、部分解析であることも結果に残します。GeoIP の有無で事案の検知フィールドのハッシュが変わらないことを確認します。異なる言語・マシン・キャッシュ条件の単発値から速度比を判断しません。

分析ルール照合・統計計算の高速化移植と、変更前後の全レポート比較・性能測定は [分析処理の高速化](docs/analysis-performance.md) を参照してください。

## 整形

Java ソースは google-java-format 2.0.0 で整形しています。開発用 formatter は製品に同梱しません。

```powershell
$files = @(rg --files src -g '*.java')
java -jar /path/to/google-java-format-2.0.0-all-deps.jar --replace $files
```

CI は Windows/Linux/macOS の JDK 25 で Maven 検証と JAR 検査を行い、Linux amd64 では通信禁止検証も行う構成です。ローカルで確認済みの OS と実測結果は [検証記録](docs/validation.md) を参照してください。

## v2.0.0監視機能

watchのOS連携はJDK 25のForeign Function & Memory APIを使います。実行可能JARには`Enable-Native-Access: ALL-UNNAMED`を設定しています。テストJVMにも同じオプションを設定し、通常の`java -jar`では追加フラグは不要です。Windowsはvolume/file indexでログの同一性を確認し、HookをJob Objectに収容します。UnixのHookは専用session/process groupで実行します。

Go版とのイベント参照値は`src/test/resources/watch-golden.json`、生成手順は`python tools/reference/generate_watch.py /path/to/webaudit --go /path/to/go`です。指定checkoutはv2.0.0のコミットに固定しています。生成用の一時ソースだけをGo側tools配下に作成し、終了時に削除します。通常のテストはGoを必要としません。

`python tools/measure_watch.py --seconds 10 --lines 100`で隔離した状態ディレクトリを使い、短時間の起動・追記監視・状態サイズを測定できます。Windowsの測定終了は強制終了なので、正常終了・Ctrl+Cの検証とは区別してください。Linuxの通信禁止試験にもwatchの保存・復元を追加しています。
