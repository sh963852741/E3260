using System;
using System.IO.Ports;
using System.Threading;
namespace lab1
{
    class Program
    {
        static bool _continue;
        static SerialPort _serialPort;

        public static void Main()
        {
            string message;
            StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
            Thread readThread = new Thread(Read);

            // 创建串口对象
            _serialPort = new SerialPort();
            int mychoose;
            Console.WriteLine("这里是A端!!!");
            Console.WriteLine("是否手动设置端口配置？0：否  1：是");

            mychoose = Convert.ToInt32(Console.ReadLine());
         
            if (mychoose == 1)
            {
                // 设置端口对象的属性
                _serialPort.PortName = SetPortName(_serialPort.PortName);
                _serialPort.BaudRate = SetPortBaudRate(_serialPort.BaudRate);
                _serialPort.Parity = SetPortParity(_serialPort.Parity);
                _serialPort.DataBits = SetPortDataBits(_serialPort.DataBits);
                _serialPort.StopBits = SetPortStopBits(_serialPort.StopBits);
                _serialPort.Handshake = SetPortHandshake(_serialPort.Handshake);
            }
            else
            {
                Console.WriteLine("您正在使用默认配置进行通信！");
                _serialPort.PortName = _serialPort.PortName;
                _serialPort.BaudRate = _serialPort.BaudRate;
                _serialPort.Parity = _serialPort.Parity;
                _serialPort.DataBits = _serialPort.DataBits;
                _serialPort.StopBits = _serialPort.StopBits;
                _serialPort.Handshake = _serialPort.Handshake;
            }
            //超时时间
            _serialPort.ReadTimeout = 500;
            _serialPort.WriteTimeout = 500;

            _serialPort.Open();
            _continue = true;
            readThread.Start();

            Console.WriteLine("退出请输入“quit”");

            while (_continue)
            {
                message = Console.ReadLine();

                if (stringComparer.Equals("quit", message))
                {
                    _continue = false;
                }
                else
                {
                    System.DateTime currentTime = new System.DateTime();
                    currentTime = System.DateTime.Now;
                    string strTime = currentTime.ToString();
                    message = "[SENT " + strTime + "] " + message;//发送信息
                    Console.WriteLine(message);//在控制台输出发送的信息
                    _serialPort.WriteLine(
                        String.Format("{0}", message));
                }
            }

            readThread.Join();
            _serialPort.Close();
        }

        public static void Read()
        {
            while (_continue)
            {
                try
                {
                    string message = _serialPort.ReadLine();
                    System.DateTime currentTime = new System.DateTime();
                    currentTime = System.DateTime.Now;
                    string strTime = currentTime.ToString();
                    message = "[REVC " + strTime + "] " + message;//接收串口信息
                    Console.WriteLine(message);//在控制台输出接收的信息
                }
                catch (TimeoutException) { }
            }
        }

        //设置端口
        public static string SetPortName(string defaultPortName)
        {
            string portName;

            Console.WriteLine("可用端口:");
            foreach (string s in SerialPort.GetPortNames())
            {
                Console.WriteLine("   {0}", s);
            }

            Console.Write("输出 COM 端口值 (默认: {0}): ", defaultPortName);
            portName = Console.ReadLine();

            if (portName == "" || !(portName.ToLower()).StartsWith("com"))
            {
                portName = defaultPortName;
            }
            return portName;
        }

        // 设置波特率
        public static int SetPortBaudRate(int defaultPortBaudRate)
        {
            string baudRate;

            Console.Write("波特率(默认:{0}): ", defaultPortBaudRate);
            baudRate = Console.ReadLine();

            if (baudRate == "")
            {
                baudRate = defaultPortBaudRate.ToString();
            }

            return int.Parse(baudRate);
        }

        // 设置端口奇偶值
        public static Parity SetPortParity(Parity defaultPortParity)
        {
            string parity;

            Console.WriteLine("可用奇偶值:");
            foreach (string s in Enum.GetNames(typeof(Parity)))
            {
                Console.WriteLine("   {0}", s);
            }

            Console.Write("可用奇偶值(默认: {0}):", defaultPortParity.ToString(), true);
            parity = Console.ReadLine();

            if (parity == "")
            {
                parity = defaultPortParity.ToString();
            }

            return (Parity)Enum.Parse(typeof(Parity), parity, true);
        }
        //设置数据位
        public static int SetPortDataBits(int defaultPortDataBits)
        {
            string dataBits;

            Console.Write("设置数据位 (默认: {0}): ", defaultPortDataBits);
            dataBits = Console.ReadLine();

            if (dataBits == "")
            {
                dataBits = defaultPortDataBits.ToString();
            }

            return int.Parse(dataBits.ToUpperInvariant());
        }

        //设置停止位
        public static StopBits SetPortStopBits(StopBits defaultPortStopBits)
        {
            string stopBits;

            Console.WriteLine("可用停止位:");
            foreach (string s in Enum.GetNames(typeof(StopBits)))
            {
                Console.WriteLine("   {0}", s);
            }

            Console.Write("输入停止位 (默认: {0}):", defaultPortStopBits.ToString());
            stopBits = Console.ReadLine();

            if (stopBits == "")
            {
                stopBits = defaultPortStopBits.ToString();
            }

            return (StopBits)Enum.Parse(typeof(StopBits), stopBits, true);
        }
        public static Handshake SetPortHandshake(Handshake defaultPortHandshake)
        {
            string handshake;

            Console.WriteLine("可用握手协议:");
            foreach (string s in Enum.GetNames(typeof(Handshake)))
            {
                Console.WriteLine("   {0}", s);
            }

            Console.Write("输入握手协议 (默认: {0}):", defaultPortHandshake.ToString());
            handshake = Console.ReadLine();

            if (handshake == "")
            {
                handshake = defaultPortHandshake.ToString();
            }

            return (Handshake)Enum.Parse(typeof(Handshake), handshake, true);
        }
    }
}
