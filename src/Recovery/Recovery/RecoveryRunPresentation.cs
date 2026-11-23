using System;
using System.Globalization;

namespace UsbRecovery
{
    // View state contains no IO and never decides whether a checkpoint is trusted.
    // It describes engine events; Resume still performs full source/output checks.
    public sealed class RecoveryRunPresentation
    {
        string stageKey;
        bool finished;
        public string Heading { get; private set; }
        public string ProgressText { get; private set; }
        public string SaveText { get; private set; }
        public string ActionText { get; private set; }
        public bool StopRequested { get; private set; }
        public bool CanContinue { get; private set; }
        public int? Percent { get; private set; }

        public RecoveryRunPresentation() { Reset(); }

        public void Reset()
        {
            Heading = "Готово к поиску";
            ProgressText = "Прогресс появится после чтения источника";
            SaveText = "Продолжение проверяет источник и сохранённые результаты";
            ActionText = "Выбери флешку, образ или сохранённый поиск";
            Percent = null;
            stageKey = null;
            finished = false;
            StopRequested = CanContinue = false;
        }

        public void Apply(RecoveryStageProgress update)
        {
            if (update == null || finished) return;
            if (update.Total > 0)
                Percent = (int)Math.Max(0, Math.Min(100, (decimal)update.Completed * 100 / update.Total));
            else if (stageKey != update.Key)
                Percent = null;
            stageKey = update.Key;
            ProgressText = Percent.HasValue
                ? Percent.Value.ToString(CultureInfo.CurrentCulture) + "% текущего этапа"
                : "Объём текущего этапа пока неизвестен";
            SaveText = update.CheckpointSequence > 0
                ? "Записана точка №" + update.CheckpointSequence.ToString(CultureInfo.CurrentCulture)
                : "Новая точка продолжения ещё не подтверждена";
            if (update.State == "reused")
            {
                ProgressText = "Готовый результат проверен и использован повторно";
                SaveText = "Повторное сканирование этого этапа не требуется";
            }
            else if (update.State == "complete")
                SaveText = "Результат этапа записан";
            if (StopRequested) return; // Late progress must not hide a stop request.
            Heading = update.Title ?? "Восстановление";
            ActionText = update.ResumingCheckpoint
                ? "Продолжаем с проверенной точки"
                : "Источник доступен только для чтения";
        }

        public void RequestStop()
        {
            if (finished) return;
            StopRequested = true;
            CanContinue = false;
            Heading = "Останавливаем поиск";
            ActionText = "Дождись остановки. Пока не закрывай программу и не отключай носитель";
        }

        public void Finish(bool completed, bool warnings, bool hasSavedJob, bool cancelled)
        {
            finished = true;
            StopRequested = false;
            CanContinue = !completed && hasSavedJob;
            if (completed)
            {
                Percent = null;
                ProgressText = warnings ? "Проверь замечания к результатам" : "Обработка завершена";
            }
            Heading = completed ? (warnings ? "Завершено с замечаниями" : "Поиск завершён")
                : cancelled ? "Поиск остановлен" : "Поиск прерван";
            ActionText = completed ? "Проверь найденные файлы перед экспортом"
                : hasSavedJob ? "Продолжить: сначала проверим источник и сохранённые данные"
                : "Сохранённая сессия не найдена — смотри подробности ошибки";
            SaveText = completed ? "Результаты доступны в папке поиска"
                : hasSavedJob ? "Для этапов без точки продолжения потребуется повторный проход"
                : "Продолжение из этой папки пока недоступно";
        }
    }
}
