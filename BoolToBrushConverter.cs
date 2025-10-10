using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Naraka_Cheat_Detector
{
    public class BoolToBrushConverter : IValueConverter
    {
        public object Convert(object value, System.Type targetType, object parameter, string language)
        {
            bool detected = false;
            if (value is bool b) detected = b;

            return new SolidColorBrush(detected ? Color.FromArgb(255, 255, 107, 107) : Color.FromArgb(255, 107, 255, 154));
        }

        public object ConvertBack(object value, System.Type targetType, object parameter, string language)
        {
            return false;
        }
    }
}
