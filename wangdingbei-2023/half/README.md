# RDG宿主机说明



## 注意事项

- 请遵守大赛规则。
- 不允许删除image，docker rmi image 后无法重置。
- 如需重置docker容器，请使用docker rm 容器 删除后,再docker run 起来。
- 宿主机资源有限，建议题目容器不使用时关闭或删除容器,以免因同时启动容器过多导致宿主机资源占满。

## docker 命令介绍

- 列举运行中的容器: docker ps;
- 进入容器中执行命令： docker exec -it 容器名 bash ；
- 容器的文件复制： docker cp --help ；
- 重启容器： docker restart 容器名 ；
- 重置容器需要docker rm 容器名, 再 docker run （详见启动命令示例)
- 其他命令：docker --help    
- 注意：不要执行docker rmi命令（非常重要）


## 容器启动命令示例

- GameCenter
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6080:80 --name  gamecenter gamecenter:latest
    ```

- Reward
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6081:80 --name  reward reward:latest
    ```

- tomcat
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6082:9981 --name  tomcat tomcat:latest
    ```

- babymaze
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6083:9999 --name  babymaze babymaze:latest
    ```

- babyshell
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6084:9999 --name  babyshell babyshell:latest
    ```

- managesys
    ```
    docker run -itd --cpu-period=100000 --cpu-quota=100000 -m 1G --device-write-bps /dev/sda:20mb --device-read-bps /dev/sda:20mb --restart=always -p 6085:9999 --name  managesys server:latest
    ```


## 其他相关命令

- 容器启动
    ```
    docker start gamecenter
    docker start reward
    docker start tomcat
    docker start babymaze
    docker start babyshell
    docker start managesys
    ```

- 容器关闭
    ```
    docker stop gamecenter
    docker stop reward
    docker stop tomcat
    docker stop babymaze
    docker stop babyshell
    docker stop manage  sys
    ```

- 容器删除
    ```
    docker rm -f gamecenter
    docker rm -f reward
    docker rm -f tomcat
    docker rm -f babymaze
    docker rm -f babyshell
    docker rm -f managesys
    ```

- 拷贝文件到容器
    ```
    /* 如拷贝文件到容器名为 tomcat 的容器中 */
    docker cp srcfile tomcat:/home/

    /* 从tomcat 容器中拷贝出来 */
    docker cp tomcat:/srcfile .
    ```

