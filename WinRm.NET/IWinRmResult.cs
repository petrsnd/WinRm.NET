namespace WinRm.NET
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public interface IWinRmResult
    {
        public bool IsSuccess { get; }

        // Contents of stdout
        // Might make more sense as a stream or something?
        public string Output { get; }

        // Contents of stderr? Does this apply in winrm?
        public string Error { get; }

        // Returns the error if IsSuccess is false
        public string ErrorMessage { get; }
    }
}
