from dj_rest_auth.serializers import UserDetailsSerializer


class CustomUserDetailsSerializer(UserDetailsSerializer):
    class Meta(UserDetailsSerializer.Meta):
        read_only_fields = UserDetailsSerializer.Meta.read_only_fields + ("username",)
