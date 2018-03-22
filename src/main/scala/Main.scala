package firesocks.client

import java.net._
import java.io._

class ClientConfig(
  val port: Int
)

object Client {
  def run(config: ClientConfig) {
    val sock = new ServerSocket(config.port, 2)
    try {
      val conn = sock.accept()
      serve(conn)
    }
    catch {
      case e: Throwable => println(e)
    }
    sock.close()
  }

  def serve(conn: Socket) {
    val in = new DataInputStream(conn.getInputStream)
    println(s"version=${in.readByte()}")
    val nm = in.readByte()
    print("methods=")
    var needauth = true
    for (i <- 1 to nm) {
      print(in.readByte() match {
        case 0x00 => { needauth = false; "None" }
        case 0x01 => "GSSAPI"
        case 0x02 => "User-Password"
        case 0x03 => "IANA-Reserved"
        case 0x80 => "User-Defined"
        case 0xFF => "Unavailable"
      })
      if (i != nm) print(",")
    }
    println()
    if (!needauth) {
      val out = new DataOutputStream(conn.getOutputStream)
      out.writeByte(5)
      out.writeByte(0)
      println(s"version=${in.readByte()}")
      println(s"cmd=${in.readByte()}")
      println(s"rsv=${in.readByte()}")
      val addrtype = in.readByte()
      println(s"addrtype=${addrtype}")
      addrtype match {
        case 0x01 => println("ipv4=${in.readInt()}")
        case 0x03 => {
          val n = in.readByte()
          for (_ <- 1 to n) {
            System.out.write(in.readByte())
          }
          println()
        }
        case 0x04 => {
          print("ipv6=")
          for (_ <- 1 to 4) print(in.readInt().toString)
          println()
        }
      }
      println(s"port=${in.readShort()}")
    }
    conn.close()
  }

  def main(args: Array[String]) {
    run(new ClientConfig(args(0).toInt))
  }
}
