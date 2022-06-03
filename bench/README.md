# bench

# TODO

- 鍵がPEM版、webappはまだ多分jwk版なので動かないです


## How to run

前提

- repo root にいる状態
- docker-compose で起動している状態
  - nginx が port 80
  - mysql が port 13306

```console
$ gh release download dummydata/20220421_0056-prod # もしくはreleaseからisucon_listen80_dump_prod.tar.gzをダウンロード
$ tar xvf isucon_listen80_dump_prod.tar.gz
$ mysql -uroot -proot --host 127.0.0.1 --port 13306 < isucon_listen80_dump.sql
$ cd bench
$ make
$ ./bench -target-url http://localhost  # nginxのportを変えている場合はportを合わせる
```


# メモ

なんとかActionでリクエストを作って送って返ってきたresをValidateResponseで検証してるんだけど、この2つの関数に関係がないのでリクエスト開始から結果取得完了までの時刻(レスポンスタイム)を元になにかするのができない
n秒超えたらタイムアウトではないけど0点、みたいな調整がやりづらいのでそこだけ作りを変えたい気持ち
リクエストを送るctxをwrapして、そこでリクエスト送信時にメタデータを入れてvalidateにもctxを渡してそれをみれるようにするとか


## シナリオ一案

2022-06-03時点

📝  comment: 整合性チェックでは入念に、負荷走行中は整合性チェックほぼしない、ただし失格403系はチェックする

### 既存テナント(初期データ)

- player追加
- 各competition
  - 終了前なら
    - CSV入稿
      - 初期データにまとまった情報jsonに入れないといけない
      - テナント内に存在するPlayerNameがあれば良い
    - 終了
  - ランキング取得
- 各player
  - :memo: 失格APIは初期データplayerに失格者が増えていって戻すのが大変なのでやらない
  - player閲覧
    - check: 失格者なら403
    - check: 複数大会に参加している参加者はそれぞれの結果があること
    - テナント内の別ユーザー参照、初期データjsonに含めないとわからない
      - benchでsqliteで読んじゃう 
      - 各playerのScoreが存在するCompetitionIDの一覧あるいは出場したcompetitionの総数
      - 総数を入れる場合はシナリオ内でCSV入稿するcompetitionと被るとズレる可能性がある
  - ranking閲覧
    - check: 失格者なら403
- 請求情報閲覧
  - check: テナント内に存在するplayer総数が合っているか
  - 初期データjsonに含めないとわからない、tenant内のplayer総数があれば良い

### 新規テナント

- player追加
  - 負荷ネタ: 1テナントのplayer数が爆増する
- competition追加
  - CSV入稿
    - 負荷ネタ: 巨大
      - 存在しないPlayerNameはエラーになりそう
      - PlayerName重複はOK 重複が多すぎてデカい
      - 失格者が多くてデカい テナントの失格者行が多い
  - 終了
  - ranking
    - check: 失格者が含まれていないこと
    - check: ページングが正しく機能していること
- 各player
  - player取得
    - check: 複数大会が含まれていること
  - ranking取得
    - check: 複数大会が含まれていること
 billing取得  
 - check: 上限20？
