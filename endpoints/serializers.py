from rest_framework import serializers
from .models import Activity, Workout

class ActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Activity
        fields = ['id', 'name', 'has_time', 'has_distance', 'distance_unit']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class WorkoutSerializer(serializers.ModelSerializer):
    activity = serializers.PrimaryKeyRelatedField(queryset = Activity.objects.all())

    class Meta:
        model = Workout
        fields = ['id', 'activity', 'date', 'time', 'distance', 'description', 'rpe']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

