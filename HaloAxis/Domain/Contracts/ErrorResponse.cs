namespace HaloAxis.Domain.Contracts
{
    public class ErrorResponse
    {
        public string Title { get; set; }
        public string Message { get; set; }
        public int StatusCode { get; set; }
    }
}
