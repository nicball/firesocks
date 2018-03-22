package firesocks.client

import java.net._
import java.io._
import firesocks.socks5._

class ClientConfig(
  val port: Int
)

object Client {
  def run(config: ClientConfig) {
    val sock = new ServerSocket(config.port, 2)
    for (_ <- 1 to 10) {
      val conn = sock.accept()
      new Thread(() => {
        try {
          serve(conn)
        }
        catch {
          case e: Throwable => println(e)
        }
        conn.close()
      }).start
    }
    sock.close()
  }

  def serve(conn: Socket) {
    import Socks5IO._
    val in = conn.getInputStream
    val out = conn.getOutputStream
    val greeting = read[Greeting](in).get
    println(greeting)
    if (!greeting.auth_methods.contains(NoAuth)) return
    write(out, GreetingResponse(Some(NoAuth)))
    val req = read[ConnectionRequest](in).get 
    println(req)
    write(out, ConnectionResponse(GeneralFailure, req.addr, req.port))
  }

  def main(args: Array[String]) {
    run(new ClientConfig(args(0).toInt))
  }
}
