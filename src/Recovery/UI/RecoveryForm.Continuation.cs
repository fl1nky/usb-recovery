using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed partial class RecoveryForm
    {
        readonly RecoveryRunPresentation runPresentation = new RecoveryRunPresentation();
        readonly RecoveryRunStatusCard runStatusCard = new RecoveryRunStatusCard();
        bool lastOperationCancelled;

        Control BuildRunStatus()
        {
            var panel = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 10) };
            progress.Dock = DockStyle.Top;
            progress.Height = 4;
            runStatusCard.Dock = DockStyle.Fill;
            runStatusCard.Present(runPresentation);
            panel.Controls.Add(runStatusCard);
            panel.Controls.Add(progress);
            // Detailed messages remain available in the expandable operation journal.
            status.Text = "Готово. Для первого запуска подходит стандартный профиль.";
            return panel;
        }

        void RequestRecoveryStop()
        {
            if (cancellation == null || cancellation.IsCancellationRequested) return;
            runPresentation.RequestStop();
            runStatusCard.Present(runPresentation);
            stop.Enabled = false;
            stop.Text = "Останавливаем…";
            status.Text = runPresentation.ActionText;
            cancellation.Cancel();
        }

        static bool HasSavedJob(string folder)
        {
            if (String.IsNullOrEmpty(folder)) return false;
            try
            {
                return File.Exists(RecoveryCatalog.SafeFile(folder, RecoverySession.FileName))
                    || File.Exists(RecoveryCatalog.SafeFile(folder, "capture-request.json"))
                    || ForensicImageSource.HasRequest(folder);
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        void CompletePresentation(bool complete, bool warnings)
        {
            runPresentation.Finish(complete, warnings, HasSavedJob(lastDirectory), lastOperationCancelled);
            runStatusCard.Present(runPresentation);
            stop.Text = "Остановить";
            continueJob.Text = runPresentation.CanContinue ? "Продолжить этот поиск" : "Открыть сохранённый…";
            continueJob.AccessibleDescription = runPresentation.CanContinue
                ? "Проверить данные и продолжить последний поиск" : "Выбрать папку другого сохранённого поиска";
        }

        async void ContinueLastJobOrChoose()
        {
            if (IsBusy) return;
            if (runPresentation.CanContinue && HasSavedJob(lastDirectory))
                await ContinueSavedJobAsync(lastDirectory);
            else
                ChooseSavedJob();
        }
    }
}
