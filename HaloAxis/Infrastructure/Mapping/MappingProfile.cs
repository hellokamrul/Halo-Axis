using AutoMapper;
using HaloAxis.Domain.Contracts;
using HaloAxis.Domain.Entities;

namespace HaloAxis.Infrastructure.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, UserResponse>().ReverseMap();
            CreateMap<ApplicationUser, CurrenUserResponse>().ReverseMap();
            CreateMap<UserRegisterRequest, ApplicationUser>().ReverseMap();

        }
    }
}
