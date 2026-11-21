# LB配下でのApache／Nginxの設定

WebAuditJはログに記録されたIPを解析します。LBやCDN、リバースプロキシが前段にある場合は、Apache／Nginx側で信頼する中継元から実クライアントIPを復元し、WebAuditJが読むIP欄に記録してください。ここでいう実クライアントIPは、信頼する中継経路から得られる接続元IPであり、個人や端末の識別を保証しません。

WebAuditJはX-Forwarded-For（XFF）、X-Real-IP、Forwardedを使ったIPの自動復元や、信頼するプロキシの設定には対応していません。ALB等の製品固有のアクセスログの直接取り込みも現状の対応範囲外です。以下はApache／NginxのHTTPアクセスログを作る例であり、各LB製品の全構成を検証したものではありません。

## 構成を確認する

| LBからバックエンドへの転送方式 | 必要な対応 |
|---|---|
| XFFなどのHTTPヘッダーで元IPを渡す | 信頼するLB・プロキシを限定してヘッダーから復元する |
| PROXY protocolで元IPを渡す | LBの送信設定とWebサーバーの受信設定をそろえる |
| ネットワーク上で元IPを保持する | 記録されたIPが期待する接続元と一致することを確認する |
| 元IPを渡さず、接続元をLBのIPに変換する | Webサーバー単独では復元できない。LB構成の変更や別のログによる調査が必要 |

例ではLBのバックエンド側IPを`10.0.1.10`とします。実際のLBの送信元IP／CIDRに置き換えてください。自動拡張等で送信元が変わる場合は、その範囲と更新方法も確認します。プライベートネットワーク全体や`0.0.0.0/0`、`::/0`を一律に信頼せず、LBに必要な範囲に限定します。

LBが外部から受け取ったXFFを上書きするのか、接続元を末尾に追加するのかも確認してください。外部から届いた値をそのまま転送する構成では、ヘッダーを偽装できます。CDN → LB → Webサーバーのような多段構成では、途中の中継元とヘッダー処理も含めて信頼範囲を定めます。XFFの左端を無条件に採用する運用にはしません。

## Nginx：XFFから復元する

`http_realip_module`が必要です。`nginx -V`のビルド情報で`--with-http_realip_module`を確認し、配布パッケージのモジュール構成も確認してください。次の例は`http`コンテキスト内に置き、`server`の名前・待受・配信設定は既存環境に合わせます。

```nginx
set_real_ip_from 10.0.1.10;
real_ip_header X-Forwarded-For;
real_ip_recursive on;

log_format webaudit_lb '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent" '
                       'peer=$realip_remote_addr';

server {
    listen 80;
    server_name app.example.com;
    access_log /var/log/nginx/webaudit-access.log webaudit_lb;
    # 既存のroot/location等の配信設定
}
```

`$remote_addr`が復元後のIP、`$realip_remote_addr`が実際に接続したLB等のIPです。`real_ip_recursive on`では、信頼する中継元からのXFFを右側からたどり、最後の信頼対象外のアドレスを採用します。多段構成では必要な中継元だけを`set_real_ip_from`に追加します。LBがX-Real-IP等を使う場合は、実際の仕様に合わせて`real_ip_header`を変更してください。[Nginx realip公式仕様](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

このログはCombined形式に`peer=...`を付加したものです。WebAuditJは先頭のIPを解析し、末尾のpeerは原文として保持します。peerを別のクライアントIPとして集計することはありません。既存のNginx JSONログを使う場合も、`remote_addr`に復元後の`$remote_addr`を記録してください。XFF用のJSONキーを追加するだけでは解析対象IPは変わりません。

## Apache 2.4：XFFから復元する

`mod_remoteip`を有効にし、`apachectl -M`（環境によって`apache2ctl -M`または`httpd -M`）で`remoteip_module`を確認します。モジュールの有効化方法やログのパスは配布パッケージに合わせてください。以下はサーバー設定または対象VirtualHost内の設定例です。

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 10.0.1.10

LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" peer=%{c}a" webaudit_lb
CustomLog /var/log/apache2/webaudit-access.log webaudit_lb
```

`%a`が復元後のIP、`%{c}a`が実際に接続したLB等のIPです。ホスト名になる可能性がある`%h`ではなく、解析対象の先頭欄に`%a`を使います。WebAuditJは末尾のpeerを原文として保持します。[Apacheログ形式の公式仕様](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)

`RemoteIPHeader`だけを指定すると送信元の信頼範囲が限定されません。必ず信頼する中継元を併せて指定してください。`RemoteIPTrustedProxy`は、LB自身がプライベートIPでも指定できます。ただし、ヘッダー内のプライベートIPをクライアントIPとして採用する用途では、必要な中継元に限って`RemoteIPInternalProxy 10.0.1.10`を代わりに使います。これはプライベートIPも含む申告値を信頼する設定なので、社内向け構成など用途を確認します。mod_remoteipはログだけでなく`Require ip`等のアクセス制御にも影響するため、既存のIP制限も確認してください。[Apache mod_remoteip公式仕様](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)

## PROXY protocolを使う場合

XFF方式の代わりに、LBがPROXY protocolを送信する構成で使います。LB側の送信設定も必要です。ヘッダー方式と不用意に併用せず、元IPの採用元を明確にします。

Nginxでは、前述のログ形式を使い、`real_ip_header`と待受を次のように変更します。

```nginx
# httpコンテキスト内
set_real_ip_from 10.0.1.10;
real_ip_header proxy_protocol;

server {
    listen 8080 proxy_protocol;
    server_name app.example.com;
    access_log /var/log/nginx/webaudit-access.log webaudit_lb;
    # 既存のroot/location等の配信設定
}
```

Apacheでは2.4.31以降の`mod_remoteip`を使い、前述の`RemoteIPHeader`／`RemoteIPTrustedProxy`の代わりに対象の待受で有効にします。`LogFormat`と`CustomLog`は前述のものを使えます。

```apache
Listen 8080
<VirtualHost *:8080>
    ServerName app.example.com
    RemoteIPProxyProtocol On
    # 前述のLogFormat/CustomLogと既存の配信設定
</VirtualHost>
```

PROXY protocolの待受ポートには、ファイアウォールやセキュリティグループで信頼するLBだけが接続できるようにしてください。特にApacheの`RemoteIPTrustedProxy`はPROXY protocolの接続元制限の代わりにはなりません。同じIP・ポートを共有するApacheのVirtualHost全体に設定が影響します。PROXY protocolを付けない通常のHTTP接続は失敗するため、ヘルスチェックの送信方式もそろえるか、別の制限された監視用ポートを用意します。[Nginx公式仕様](https://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_header)、[Apache公式仕様](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html#remoteipproxyprotocol)

## 動作確認手順

以下のシェル例はLinux向けです。ホスト名・パス・コマンド名は環境に合わせ、`/path/to/webauditJ.jar`にはJava 25以上で実行するJARのパスを指定します。出力レポートには既存ファイルと重ならない名前を使います。本資料の設定例は公式仕様とWebAuditJのパーサに照らして確認しており、実際のLB／Webサーバーを起動した結合試験は行っていません。導入先で次の確認を実施してください。

1. **構文とモジュールを確認して反映する。** Nginxは`nginx -t`、Apacheは`apachectl configtest`を実行します。成功後、環境のサービス管理手順でreloadまたは必要な再起動を行います。既存のIP制限とヘルスチェックも確認します。
2. **既知の接続元からLB経由でアクセスする。** 次のように識別できる無害なURLで送信し、各バックエンドのログを調べます。NATやVPNを通る場合、期待するのはLBから見える出口IPです。

   ```sh
   curl -sS -o /dev/null 'https://app.example.com/?webaudit-lb-check=normal-001'
   ```

   先頭が期待する接続元IP、末尾の`peer=`がLBのバックエンド側IPになっていることを確認します。例は次の形です（IPと時刻は例示）。HTTPステータスが200以外でも、IPの確認はできます。

   ```text
   198.51.100.25 - - [21/Nov/2026:12:00:00 +0900] "GET /?webaudit-lb-check=normal-001 HTTP/1.1" 200 42 "-" "curl/8.0" peer=10.0.1.10
   ```

3. **異なる出口IPの端末でも確認する。** もう一つのネットワークから別の識別子で送信し、先頭のIPが分かれることを確認します。同じNAT配下の端末同士では分かれません。多段構成では、CDNや途中のプロキシのIPが採用されず、期待する出口IPが記録されることも確認します。
4. **偽装XFFが採用されないことを確認する。** XFF方式では、一般のクライアントからLB経由で次を送信します。

   ```sh
   curl -sS -o /dev/null -H 'X-Forwarded-For: 203.0.113.123' \
     'https://app.example.com/?webaudit-lb-check=spoof-001'
   ```

   先頭のIPが申告した`203.0.113.123`ではなく、実際の出口IPになることを確認します。LBによる上書き、または正しい追記と信頼チェーンの処理が必要です。バックエンドへの直接接続を許す構成では、信頼対象外の検証端末からも同様に確認し、XFFが無視されることを確認します。直接接続を禁止する構成では、接続自体が遮断されることを確認します。
5. **PROXY protocol方式は実際のLB経由で確認する。** 通常のcurlでPROXY protocol専用ポートへ直接接続する試験は成功を期待しません。LBからの通信とヘルスチェックが成功し、許可していない接続元からは到達できないことを確認します。
6. **確認行をWebAuditJで解析する。** 識別子の付いた行だけを専用ファイルに保存し、元ログと照合します。Nginxの例です。

   ```sh
   rg 'webaudit-lb-check=' /var/log/nginx/webaudit-access.log > lb-check.log
   java -jar /path/to/webauditJ.jar lb-check.log --verbose --format json -o lb-check-report.json
   ```

   Apacheでは入力パスを置き換えます。診断で全確認行が解析され、未解析行がないことを確認します。無害なURLでは事案が作られない場合があるため、レポートにIPが出ないことだけで失敗とは判定しません。curlのUAが検出条件に該当する場合もあります。採用IPの正しさは元ログの先頭欄で確認します。WebAuditJの「解析成功」は、LBの信頼設定や元IPの正しさを検証した意味ではありません。プロキシ構成が不明である旨の一般警告は、復元が正しく設定されていても表示されます。

同一リクエストを異なるログ形式で二重に記録した場合、確認には片方だけを使います。WebAuditJは同一要求を自動で名寄せしません。アクセスログで復元できても、エラーログは出力段階や形式により接続元の意味が異なるため、別途実ログを確認してください。

## IP集計への影響と過去ログの限界

| 記録されたIPの状態 | WebAuditJでの影響 |
|---|---|
| 全利用者が同じLBのIPになる | IP単位の件数・頻度・UAの種類などが混合し、過剰な頻度検出等につながる可能性がある |
| 同じ利用者が複数LBのIPに分かれる | IP単位の集計が分散し、閾値に届かず見逃す可能性がある |
| 正しい元IPを記録する | そのIPを基準に集計できる。ただしNAT・共有プロキシ等で複数利用者が同じIPを共有する場合は残る |
| 偽装したヘッダー値をIP欄に記録する | 攻撃者がIP集計を分散させたり、第三者のIPへ帰属させたりできる |

URL・UA等の文字列を検査する検出は実行されますが、その結果の帰属先も記録されたIPです。事案集約はIPだけでなく、対象ホスト・UA・手法・5分の時間区分も使うため、LB配下の全要求が必ず一つの事案になるわけではありません。Hub互換検出のグループ化もルールによりIP、IPとホスト、IPとパス等で異なります。

GeoIPの国・ASNも記録されたIPを参照します。LBのIPならLB側の情報、プライベートIPならその分類となり、利用者の国・ASNを示しません。GeoIPは調査の補助情報であり、検知や成否スコアには使いません。

ログにLBのIPしか残っていなければ、WebAuditJ単独では元IPを復元できません。XFFが末尾に残っていても、当時の中継構成と上書き／追記の仕様が不明なまま採用しないでください。必要に応じてLB／CDN側のログを、時刻・対象URL・リクエストID等で照合します。`--log-regex`で`ip`を指定する機能は、信頼するプロキシを検証する機能ではありません。

設定変更は過去ログに遡って適用されません。変更前後のログは区別し、切替時刻と信頼範囲を記録してください。変更前に同じLBのIPへ集計された結果が、自動で個別の元IPへ再配分されることはありません。

## 参考

本ガイドはGo版webauditの[LB配下でのApache／Nginxの設定](https://github.com/mikoto2000/webaudit/blob/bf4e97cc7a673e9bd10a06446b4019a1a4b00304/docs/load-balancer.md)を基に、WebAuditJの実行方法と現行の解析仕様に合わせています。
