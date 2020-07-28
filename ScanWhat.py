import socket
import threading
import re
import os
import time
import webbrowser
from datetime import datetime, date
from queue import Queue
from tkinter import *
from tkinter import messagebox, simpledialog, ttk, filedialog
from tkinter.ttk import Treeview
import ipaddress


class build_scanner(Tk):
    """
The class inherits from TK, which is a part of the tkinter library, thereby enabling the creation of a GUI for
the program and containing the construction process and a variety of methods that offer customer-level service.
    """
    def __init__(self):
        """
        Our constructor is responsible for building the GUI and after building the GUI Initialize the components
        """
        super().__init__()
        self.geometry("450x300")
        self._frame_Profile = Frame(self)
        self._frame_target = Frame(self)
        self._frame_btn = Frame(self)
        self._label_name = Label(self, text="ScanWhat?", compound=CENTER, height=3, font=("Courier", 16, "bold"))
        self._label_name.pack()
        self._text_content = StringVar()
        self._entry_target = Entry(self._frame_target, textvariable=self._text_content, width=25,
                                   font=("Helvetica", 8, "bold"))
        self._entry_target.pack(side=RIGHT, pady=20)
        self._label_target = Label(self._frame_target, text="Target:", width=8, height=5,
                                   font=("Helvetica", 10, "bold"))
        self._label_target.pack(side=LEFT)
        self._combox = ttk.Combobox(self._frame_Profile, width=20, height=10, font=("Helvetica", 8, "bold"))
        self.option_items = ['Port scan', 'Ping scan']
        self._combox['values'] = self.option_items
        self._label_profile = Label(self._frame_Profile, text="Profile: ", width=8, font=("Helvetica", 10, "bold"))
        self._label_profile.pack(side=LEFT)
        self._combox.pack()
        self.res_ = []
        self.file_index = 0
        self._timer = 0.0
        self._q = Queue()
        self._frame_target.pack(side=TOP)
        self._frame_Profile.pack(side=TOP)
        self.assembly_components()

    def assembly_components(self):
        """
        Function - assembly_components activates the construction process of the main menu and the SCAN button
        """
        self.build_menu()
        self.scan_btn = Button(self, text="Scan", compound=CENTER, font=("Helvetica", 10, "bold"), width=10, height=2,
                               background="light grey", command=self.check_combobox)
        self.scan_btn.pack(side=BOTTOM, pady=40)

    def check_combobox(self):
        """
        Function - check_combobox Finally check what the user chooses in which type of action and
        according to this activates the required function
        """
        if self._combox.get() == "Port scan":
            self.res_ = []
            self.execute_scan_port()
        elif self._combox.get() == "Ping scan":
            self.res_ = []
            self.execute_scan_ping()
        else:
            messagebox.showinfo("Message", "Try again!")

    def execute_scan_ping(self):
        """
         Function - execute_scan_ping checks the desired IP address whether it is valid or not if it is valid you will
         continue the process and ask the user for the desired address range if you do not issue a message
         accordingly according to the error
        """
        try:
            if self.check_ip(self._text_content.get()):
                try:
                    self._start_range = simpledialog.askstring("Message", "Enter start range: ")
                    if int(self._start_range) > 255 or int(self._start_range) < 0:
                        messagebox.showinfo('Message', "start range can't be less then 0 and higher then 255")
                        return
                    self._end_range = simpledialog.askstring("Message", "Enter end range: ")
                    if int(self._end_range) < int(self._start_range) or int(self._end_range) > 255:
                        messagebox.showinfo('Message', "end range must be higher then start range and less then 255")
                    else:
                        if self.build_handshake():
                            self.result_screen()
                except KeyboardInterrupt and ValueError as ev:
                    messagebox.showinfo('Message', ev)
            else:
                messagebox.showinfo('Message', "Must be an ip address")
        except Exception as ev:
            messagebox.showinfo('Message', ev)

    def process_of_duration(self):
        """
        Function - process_of_duration is responsible for bringing the requested action in a separate thread
        """
        if self._combox.get() == "Port scan":
            self.start_thread()
        elif self._combox.get() == "Ping scan":
            self.turn_on()
        self.pb_hD.stop()
        self.t.quit()

    def task(self):
        """
        function-task creates the frame GUI a which represents the progress of the process
        """
        self.fb = Frame(self.t)
        self.fb.pack(expand=True, fill=BOTH, side=TOP)
        Label(self.fb, text="scanning.....", height=2, font=("Courier", 8, "bold")).pack(side=TOP)
        self.pb_hD = ttk.Progressbar(self.fb, orient='horizontal', mode='indeterminate')
        self.pb_hD.pack(expand=True, fill=BOTH, side=TOP, padx=10, pady=20)
        self.pb_hD.start(10)
        self.t.resizable(False, False)
        self.t.overrideredirect(1)
        self.t.protocol("WM_DELETE_WINDOW", self.shutdown_ttk_repeat)
        self.t.mainloop()

    def shutdown_ttk_repeat(self):
        """
        Function-shutdown_ttk_repeat that does a protocol job that closes the GUI window closing smoothly without
         any interruptions that may be
        """
        self.t.eval('::ttk::CancelRepeat')
        self.t.destroy()

    def execute_scan_port(self):
        """
        Function-execute_scan_port Performs a port scan on an IP address while checking the correctness of the process's
         IP input if after the test there are errors messages will be displayed accordingly
        """
        try:
            if len(self._text_content.get()) > 0:
                self.scan_btn.config(state='disabled')
                if self.check_ip(socket.gethostbyname(self._text_content.get())):
                    self.t = Tk()
                    thread = threading.Thread(target=self.process_of_duration)
                    thread.start()
                    self.task()
                    thread.join()
                    self.t.destroy()
                    self.result_screen()
            else:
                messagebox.showinfo("Message", "Enter target!")
        except socket.gaierror or socket.error as ev:
            self.scan_btn.config(state='normal')
            messagebox.showerror("Error", "Invalid target:  {}, Enter a host or IP address.".format(ev))
        except UnicodeError as er:
            self.scan_btn.config(state='normal')
            messagebox.showerror("Error", "Invalid target:  {}, Enter a host or IP address.".format(er))


    def check_ip(self, ip_addr):
        """
        check_ip A function that receives an IP address, the correctness of the
         address and returns a reply at the same time
         param:ip_addr:Represents an address entered by the user
         type ip_addr:String
         return:Answer
         rtype:boolean
        """
        regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
        # pass the regular expression
        # and the string in search() method
        if re.search(regex, ip_addr):
            return True
        else:
            return False

    def scan_ports(self, task):
        """
        The scan_ports function scans the received port with the IP address and checks if the port is open or closed
        and returns a reply if there is an error in scanning or checking a message is displayed accordingly
        param:task:Scroll port number to scan
        type task:int
        return:result_:Result of the scan
        rtype:list
        """
        dic = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: 'DNS', 80: "HTTP", 110: "POP3", 111: "Rpcbind",
               135: "MSRPC",
               139: "NetBios-SSN", 143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS", 993: "Imaps", 995: "Pop3s",
               1433: "SQL Server",
               1723: "PPTP", 3306: "MYSQL", 3389: "MS-WBT-SERVER", 5900: "VNC", 8080: "HTTP-Proxy", 161: "SNMP",
               666: "Airserv-ng",
               1080: "SOCKS", 6660: "IRC", 6669: "IRC", 31337: "BOABO200"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = sock.connect_ex((self._target_ip, task))
            if result == 0:
                with self._lock:
                    result_ = [task, dic[task], "Open"]
            elif result != 0:
                with self._lock:
                    result_ = [task, dic[task], "Close"]
            sock.close()
            return result_
        except socket.gaierror as msg:
            messagebox.showinfo("Message", msg)
            sys.exit()
        except socket.error as msg:
            messagebox.showinfo("Message", msg)
            sys.exit()

    def order_parm_manag(self):
        """
        The method responsible for the order of the received ports,
        and sending each port for scanning, after the task (port scanning) is completed,
        the method will end until the next scan operation.
        """
        while True:
            port = self._q.get()
            self.res_.append(self.scan_ports(port))
            self._q.task_done()

    def start_thread(self):
        """
        The start_thread function is responsible for managing
        all running processes and running each process on its own
        """
        socket.setdefaulttimeout(0.25)
        target = self._text_content.get()
        try:  # lock  the thread execution. cannot change the value of the variable inside the block at the same time.
            self._lock = threading.Lock()
            self._target_ip = socket.gethostbyname(target)
            startTime = time.time()

            for x in range(100):
                t_ = threading.Thread(target=self.order_parm_manag)
                t_.daemon = True
                t_.start()
            port_list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 666, 993, 995, 1080, 1433,
                         1723,
                         3306,
                         3389, 5900, 6660, 6669, 8080, 31337]

            # The queue module implements multi-producer, multi-consumer queues.
            # It is especially useful in threaded programming when information must be exchanged safely
            # between multiple threads. The Queue class in this module implements all the required
            # locking semantics.
            for port in port_list:
                self._q.put(port)
                self._q.join()
                self._timer = time.time() - startTime
        except socket.gaierror or socket.error as ev:
            messagebox.showerror("Error", ev)

    def build_handshake(self):
        """
        The build_handshake function is responsible for performing an address check and raises the range by 1 for
        progress in the range after completing operations Returns an answer if a process was performed successfully or
         not at all Announces errors accordingly
         return: Answer
         rtype:boolean
        """
        try:
            if self.check_ip(self._text_content.get()):
                self.scan_btn.config(state='disabled')
                self._work_net = self._text_content.get().split('.')
                dot = '.'
                self._work_net = self._work_net[0] + dot + self._work_net[1] + dot + self._work_net[2] + dot
                self._end_range = int(self._end_range) + 1
                t1 = datetime.now()
                self.t = Tk()
                thread = threading.Thread(target=self.process_of_duration)
                thread.start()
                self.task()
                thread.join()
                self.t.destroy()
                t2 = datetime.now()
                self._timer = t2 - t1  # the time needed to complete
                return True
            else:
                messagebox.showinfo("Message", "Invalid Ip address")
                return False
        except KeyboardInterrupt and ValueError:
            messagebox.showinfo("Message", "You pressed Ctrl+C")
            return False
        except Exception as ev:
            messagebox.showinfo("Message", ev)
            return False

    def turn_on(self):
        """
           turn_on() method responsible for the process of scan ping along the required range of addresses
        """
        for ip in range(int(self._start_range), self._end_range):
            ip_address = self._work_net + str(ip)
            if self.run_scan(ip_address):  # scan the address that later uses the socket.
                self.res_.append([ip_address, "A Live"])
            else:
                self.res_.append([ip_address, "Not Respond"])

    def run_scan(self, ip_address):
        """
        run_scan() is a method that receives an ip address, the method will ping scan all the received address and return 1
        if the address is active (live) otherwise return 0 (does not respond).
        :param ip_address:
        :return :1 the address is active (live):
        :return :0  address does not respond
        """
        try:  # scan the ip range
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip_address, 445))  # gives the response about the host
            if result == 0:
                return 1
            else:
                return 0
        except KeyboardInterrupt and ValueError:
            messagebox.showinfo("Message", "You pressed Ctrl+C")
            self.t.destroy()

        except socket.gaierror:
            messagebox.showinfo("Message", 'Hostname could not be resolved. Exiting')
            self.t.destroy

        except socket.error:
            messagebox.showinfo("Message", "Couldn't connect to server")
            self.t.destroy()

    def result_screen(self):
        """
        result_screen() a method responsible for creating a frame (gui),
        a window in which the results of the task selected by the user will be displayed on the address entered.
        """
        self.scan_btn.config(state='normal')
        new_window = Toplevel(self)
        new_window.title("SW?")
        new_window.geometry("600x550")
        new_window.resizable(False, False)
        Label(new_window, text="Scan Result", height=2, font=("Courier", 16, "bold")).pack(side=TOP)
        if self._combox.get() == "Port scan":
            ip_t = Label(new_window, text="Ip address = " + self._target_ip + "\n\nTime taken: " + str(self._timer),
                         foreground="red", width=50, height=5, font=("Helvetica", 10, "bold"))
            ip_t.pack(side=TOP, padx=10)
            table = Treeview(new_window, columns=(1, 2, 3), show='headings', height=6)
            table.pack(side=TOP, padx=10)
            table.heading(1, text="Port")
            table.heading(2, text="Service")
            table.heading(3, text='Status')
        else:
            ip_t = Label(new_window,
                         text="Ip address = " + self._text_content.get() + "\n\nTime taken: " + str(self._timer),
                         foreground="red", width=50, height=5, font=("Helvetica", 10, "bold"))
            ip_t.pack(side=TOP, padx=10)
            table = Treeview(new_window, columns=(1, 2), show='headings', height=6)
            table.pack(side=TOP, padx=10)
            table.heading(1, text="Ip Address")
            table.heading(2, text="Status")

        if self.res_:
            # self.res_ = list(dict.fromkeys(dup))
            for l in self.res_:
                table.insert("", END, values=l)
        self._btn_save = Button(new_window, text="Save", font=("Helvetica", 10, "bold"), width=10,
                                height=2, background="light grey", command=self.save_file).pack(side=RIGHT, padx=40)
        self._btn_close = Button(new_window, text="Close", compound=CENTER, font=("Helvetica", 10, "bold"), width=10,
                                 height=2, background="light grey", command=new_window.destroy).pack(side=LEFT, padx=40)

    def ask_files(self):
        """
        This method opens another gui session as an option to select a record file from previous scans
        :return: :file chosen by user else none
        :rtype .text file
        """
        open_opt = Tk()
        open_opt.withdraw()
        file = filedialog.askopenfile(mode='r', filetypes=[('records', '*.txt')], )
        if file is not None:
            return file
        return None

    def open_record(self):
        """
        open_record(), This method will know how to take the user-selected record file,
        open a new gui session and display the selected gui session content as a list.
        """
        file_name = self.ask_files()
        if file_name:
            name = file_name.name.split('/')
            name = name[len(name) - 1].replace(".txt", "")
            file_list = file_name.read().split("\n")
            window = Toplevel(self)
            window.title("ScanWhat?")
            window.resizable(False, False)
            window.geometry("400x400")
            Label(window, text="File: {}".format(name), height=1, font=("Courier", 15, "bold")).pack(side=TOP)
            list_b = Listbox(window, width=100, height=20, font=("Courier", 8))
            list_b.pack(pady=10)
            for line in file_list:
                list_b.insert(END, line)
            Button(window, text="Close", compound=CENTER, font=("Helvetica", 10, "bold"), width=10,
                   height=1, background="light grey", command=window.destroy).pack(padx=40)

    def is_exist(self, name, path):
        """
        is_exist(name, path)
        This method has two parameters,
        a file\folder name and a path, the method checks if there is a file  or folder  with the same name in the path
        :param name:
        :param path:
        :return: :true if there is
        :return :false if it is not
        :rtype :boolean
        """
        for root, dirs, files in os.walk(path):
            if name in files or name in dirs:
                return True
        return False

    def save_file(self):
        """
        save_file(self):
        A method that saves the file of the task performed, the method will save
        the file and even if necessary create a folder relevant to the subject of the action first,
        and then save the file within it.
        """
        if self._combox.get() == "Port scan":
            if not self.is_exist('port records', r"/\\"):
                try:
                    os.makedirs(r'D:\Python project\Scanner\port records')
                except OSError:
                    messagebox.showerror('Message', r"Creation of the directory D:\Python project\Scanner\
                    port records failed")
            while self.is_exist("records_#" + str(self.file_index) + ".txt",
                                r"/port records\\"):
                self.file_index = self.file_index + 1
            try:
                open_file = open(
                    r"D:\Python project\Scanner\port records\records_#" + str(self.file_index) + ".txt",
                    'a')
                for line in self.res_:
                    open_file.writelines("Port  {}, Service:  {}, Status:  {}\n".format(line[0], line[1], line[2]))
                open_file.write("\n\nIp address: {}\nTimer: {}\nDate: {}".
                                format(self._target_ip, self._timer, date.today()))
                open_file.close()
                messagebox.showinfo("Message", "Recode successfully saved")
            except FileNotFoundError as er:
                messagebox.showerror("Message", er)
        elif self._combox.get() == "Ping scan":
            if not self.is_exist('ping records', r"/\\"):
                try:
                    os.makedirs(r'D:\Python project\Scanner\ping records')
                except OSError:
                    messagebox.showerror('Message', r"Creation of the directory D:\Python project\Scanner\
                               ping records failed")
            while self.is_exist("record_#" + str(self.file_index) + ".txt",
                                r"/ping records\\"):
                self.file_index = self.file_index + 1
            try:
                open_file = open(r"D:\Python project\Scanner\ping records\record_#" + str(self.file_index) + ".txt",
                                 'a')
                for line in self.res_:
                    open_file.writelines("Address {}, Status:{}\n".format(line[0], line[1]))
                open_file.write("\n\nIp address: {}\nTimer: {}\nDate: {}".
                                format(self._text_content.get(), self._timer, date.today()))
                open_file.close()
                messagebox.showinfo("Message", "Recode successfully saved")
            except FileNotFoundError as er:
                messagebox.showerror("Message", er)

    def show_about_ports(self, wind):
        """
        show_about_ports(self, wind)
        This method will display the full list of ports at the touch of a button in the menu displayed in gui.
         The list of ports will be displayed with a detail about the port
        :param wind:
        """
        dic = {21: "File Transfer Protocol", 22: "Secure Shell", 23: "Telnet", 25: "Simple Mail Transfer Protocol ",
               53: 'Domain Name System ', 80: "Hypertext Transfer Protocol", 110: "Post Office Protocol, version 3",
               111: "port mapper", 135: "Microsoft Remote Procedure Call", 139: "NetBios-SSN",
               143: " Internet Message Access Protocol ", 443: "Hypertext Transfer Protocol Secure",
               445: "Microsoft-DS",
               993: "Internet Message Access Protocol over TLS/SSL", 995: "Post Office Protocol 3 over TLS/SSL",
               1433: "SQL Server", 1723: "Point-to-Point Tunneling Protocol", 3306: "MYSQL",
               3389: "MS-WBT-SERVER", 5900: "Virtual Network Computing", 8080: "HTTP-Proxy",
               161: "Simple Network Management Protocol ", 666: "Airserv-ng",
               1080: "SOCKS", 6660: "Internet Relay Chat ", 6669: "Internet Relay Chat",
               31337: "Back Orifice and Back Orifice 2000"}
        port_list = Listbox(wind, width=50, height=10, font=("Courier", 10))
        port_list.pack(pady=10)
        index = 1
        for key in dic.keys():
            port_list.insert(END, "{}. port {} - {}".format(index, key, dic[key]))
            index += 1

    def callback(self, url):
        """
        This method opens the local browser window when the user clicks on the link to the site
        :param url:
        """
        webbrowser.open_new(url)

    def about_menu(self, arg):
        """
        This method is responsible for the process of building an option window displayed in the main menu,
        this method will work by the user clicking on a button displayed in the main menu bar
        :param arg:
        """
        window = Toplevel(self)
        window.title("About")
        window.geometry("400x250")
        window.resizable(False, False)
        if arg == 1:
            window.title("Ports Info")
            window.geometry("450x400")
            Label(window, text="Port List", height=1, font=("Courier", 16, "bold")).pack(side=TOP)
            self.show_about_ports(window)
            Label(window, text="Links for more details:", compound=CENTER, height=2, fg="red",
                  font=("Helvetica", 8, "bold")).pack()
            link1 = Label(window, text="Wikipedia", compound=CENTER, height=2, font=("Helvetica", 8, "bold")
                          , fg="blue", cursor="hand2")
            link1.pack()
            link1.bind("<Button-1>",
                       lambda e: self.callback("https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"))
            link2 = Label(window, text="Speedguide", compound=CENTER, height=2, fg="blue", cursor="hand2",
                          font=("Helvetica", 8, "bold"))
            link2.pack()
            link2.bind("<Button-1>",
                       lambda e: self.callback("https://www.speedguide.net/port.php?port=3389"))
            Button(window, text="Close", compound=CENTER, font=("Helvetica", 10, "bold"), width=10,
                   height=1, background="light grey", command=window.destroy).pack(padx=40)
        elif arg == 2:
            Label(window, text="ScanWhat? 1.0", height=1, font=("Helvetica", 16, "bold")).pack(side=TOP)
            Label(window, text="Copyright 2020 S.R ", height=1, font=("Helvetica", 7, "")).pack(side=TOP)
            Label(window,
                  text="Confidentiality: Open ports (actually the programs listening and\nresponding at them)"
                       "  may reveal information about the system\nor network architecture.\n"
                       "Integrity: Without open port controls, software can open any\n"
                       "candidate port and immediately communicate unhindered.\n"
                       "This is often relied upon by games, chat programs and other useful\n"
                       "software, but is undesirable for malware.\n"
                       "Availability: The network stack and the programs at open ports,\neven if the requests "
                       "are invalid, still\nprocess incoming traffic.",
                  width=55, height=50, compound=CENTER, font=("Helvetica", 8, "bold")).pack(side=TOP)

    def my_local_ip(self):
        """
        my_local_ip(self)
        This method will create an option window displayed on the main menu bar
        After pressing the user's button on the relevant option.
        """
        window = Toplevel(self)
        window.title("My local IP?")
        window.geometry("350x150")
        window.resizable(False, False)
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        Label(window, text="Host Name: {}".format(hostname), compound=CENTER,
              height=4, font=("Courier", 10, "bold"), fg="blue").pack()
        Label(window, text="Local Ip Address: {}".format(IPAddr), compound=CENTER,
              height=2, font=("Courier", 10, "bold"), fg="blue").pack(side=TOP)
        Button(window, text="Close", compound=CENTER, font=("Helvetica", 10, "bold"), width=10,
               height=1, background="light grey", command=window.destroy).pack(padx=20)

    def get_network_detail(self):
        """
        This method will open a gui session in which the user's network information will be displayed
        """
        try:
            ip_address = simpledialog.askstring("Input Ip Address", "Enter Target: ")
            ipaddress.ip_address(ip_address)
            if ip_address:
                window = Toplevel(self)
                window.title("Get Network Detail")
                window.geometry("350x200")
                window.resizable(False, False)
                detail_list = Listbox(window, width=50, height=10, font=("Courier", 8, "bold"), fg="red")
                detail_list.pack()
                detail_list.insert(END, "Ip address: {}".format(ip_address))
                net4 = ipaddress.ip_address(ip_address)
                detail_list.insert(END, "Ip version: {}".format(net4.version))
                net4 = ipaddress.ip_network(ip_address)
                detail_list.insert(END, "individual addresses in the network: {}".format(net4.num_addresses))
                detail_list.insert(END, "Netmask: {}".format(net4.netmask))
                detail_list.insert(END, "Hostmask: {}".format(net4.hostmask))
                Button(window, text="Close", compound=CENTER, font=("Helvetica", 10, "bold"), width=10,
                       height=1, background="light grey", command=window.destroy).pack(padx=40)

        except ValueError or ipaddress.AddressValueError as ex:
            messagebox.showerror("Error", ex)
        except KeyboardInterrupt or ipaddress.NetmaskValueError as e:
            messagebox.showerror("Error", e)

    def build_menu(self):
        """
        This method is responsible for building the main menu bar
        """
        menu = Menu(self)
        self.config(menu=menu)
        menu_list = Menu(menu)
        check_option = Menu(menu)
        about_ports = Menu(menu)
        menu.add_cascade(label="File", menu=menu_list)
        menu_list.add_command(label="Open record", font=("Helvetica", 8, "bold"), command=self.open_record)
        menu_list.add_separator()
        menu_list.add_command(label="Exit", font=("Helvetica", 8, "bold"), command=self.quit)
        check_option.add_cascade(label="My Local Ip?", font=("Helvetica", 8, "bold"), command=self.my_local_ip)
        check_option.add_cascade(label="Get Network Detail", font=("Helvetica", 8, "bold"),
                                 command=self.get_network_detail)
        menu.add_cascade(label="Option", menu=check_option)
        about_ports.add_cascade(label="Ports Info", font=("Helvetica", 8, "bold"), command=lambda: self.about_menu(1))
        about_ports.add_cascade(label="About", font=("Helvetica", 8, "bold"), command=lambda: self.about_menu(2))
        menu.add_cascade(label="Info", menu=about_ports)


def main():
    """
    A main method in which all the magic will take place
    """
    app = build_scanner()  # build the program
    app.title("ScanWhat?")  # the title of the program
    app.resizable(False, False)
    app.mainloop()  # run it


if __name__ == '__main__':
    main()  # main method
