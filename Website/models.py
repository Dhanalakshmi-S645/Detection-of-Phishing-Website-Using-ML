from django.db import models

# Create your models here.
class Phishing(models.Model):
    url=models.TextField()
    output=models.CharField(max_length=500)