using System.Threading;
using System.Windows.Forms;

namespace UsbRecovery
{
    public static class Program
    {
        [System.STAThread]
        public static void Main(string[] args)
        {
            if(args!=null&&args.Length>0&&args[0]=="--document-preview-worker"){
                System.Environment.ExitCode=DocumentPreviewWorker.RunConsole(args);
                return;
            }
            if(args!=null&&args.Length>0&&args[0]=="--local-media-preview-worker"){
                System.Environment.ExitCode=LocalMediaPreviewWorker.RunConsole(args);
                return;
            }
            if(args!=null&&args.Length>0&&args[0]=="--media-decode-worker"){
                System.Environment.ExitCode=MediaDecodeWorker.RunConsole(args);
                return;
            }
            if(CommandLineHandler.IsCliCommand(args)){
                System.Environment.ExitCode=CommandLineHandler.Run(args);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new RecoveryHub());
        }

        public static string WriteGallery(string directory)
        {
            return PhotoCatalog.Build(directory, CancellationToken.None, text => { });
        }
    }
}
