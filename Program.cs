using FileShare;

Console.WriteLine($"Permissions: {Connection.AssignPrivillages()}");
await FileTransmission.Send(@"C:\Users\Joseph\Documents\hello.gif", "105.107.58.215", 8888);